import logging
import os
import re
import mimetypes
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle
import pdfplumber
from spf import check2 as spf_check
from email_validator import validate_email, EmailNotValidError
from dkim import verify as dkim_verify
from urlextract import URLExtract
from .models import PDFAnalysis, UserProfile
from .serializers import RegisterSerializer
from django.http import FileResponse, HttpResponse
from django.views import View


logger = logging.getLogger(__name__)

class AnalyzePDF(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info("PDF analysis request received")
        pdf_file = request.FILES.get('pdf')
        
        if not pdf_file:
            logger.error("No PDF file provided")
            return Response({"error": "PDF file is required."}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Processing PDF: {pdf_file.name}")
        
        text = ""
        temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_pdfs')
        os.makedirs(temp_dir, exist_ok=True)
        pdf_path = os.path.join(temp_dir, pdf_file.name)
        
        try:
            # Save the uploaded PDF
            with open(pdf_path, 'wb+') as destination:
                for chunk in pdf_file.chunks():
                    destination.write(chunk)
            
            logger.info(f"PDF saved to: {pdf_path}")

            # Extract text from PDF
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text

            logger.info(f"Extracted text length: {len(text)}")

            # Initialize analysis variables
            phishing_indicators = []
            warnings = []
            phishing_urls = []
            extractor = URLExtract()

            footer_patterns = [
                r"https?://mail\.google\.com.*",
                r"file://.*",
                r"https?://.*#\d+",
                r"Page \d+ of \d+",
            ]

            # Check for suspicious keywords
            suspicious_keywords = ["urgent", "account suspended", "verify now", "click here", 
                                   "confirm your account", "unusual activity", "suspended", 
                                   "verify your identity", "update payment"]
            found_keywords = [kw for kw in suspicious_keywords if kw in text.lower()]
            if found_keywords:
                phishing_indicators.append(f"Suspicious keywords: {', '.join(found_keywords)}")

            # Extract and analyze URLs
            urls = extractor.find_urls(text)
            logger.info(f"Found {len(urls)} URLs")
            
            if urls:
                for url in urls:
                    # Skip footer URLs
                    if any(re.search(pattern, url) for pattern in footer_patterns):
                        warnings.append(f"Ignored footer URL: {url}")
                        continue
                    
                    # Check for suspicious URL patterns
                    if "login" in url.lower() or len(url) > 100 or "http://" in url:
                        phishing_indicators.append(f"Suspicious URL detected: {url}")
                        phishing_urls.append(url)
                    else:
                        warnings.append(f"Safe URL found: {url}")
            else:
                warnings.append("No URLs found in document")

            # Check sender email
            sender_match = re.search(r'From: .*?([\w\.-]+@[\w\.-]+)', text)
            if sender_match:
                sender_email = sender_match.group(1)
                try:
                    validated = validate_email(sender_email, check_deliverability=False)
                    warnings.append(f"Sender email syntax valid: {validated.email}")
                except EmailNotValidError as e:
                    phishing_indicators.append(f"Invalid sender email: {str(e)}")

                # SPF check
                ip_match = re.search(r'Received: from .*?\(.*?(\d+\.\d+\.\d+\.\d+)', text)
                if ip_match:
                    sender_ip = ip_match.group(1)
                    domain = sender_email.split('@')[1]
                    try:
                        spf_result = spf_check(i=sender_ip, s=sender_email, h=domain)
                        if spf_result[0] != 'pass':
                            phishing_indicators.append(f"SPF check failed: {spf_result[0]}")
                        else:
                            warnings.append("SPF check passed")
                    except Exception as e:
                        warnings.append(f"SPF check error: {str(e)}")
                else:
                    warnings.append("No sender IP found for SPF check")
            else:
                warnings.append("No sender email found")

            # DKIM check
            dkim_match = re.search(r'DKIM-Signature:.*$', text, re.MULTILINE)
            if dkim_match:
                try:
                    if not dkim_verify(text.encode()):
                        phishing_indicators.append("DKIM verification failed")
                    else:
                        warnings.append("DKIM signature verified")
                except Exception as e:
                    warnings.append(f"DKIM check error: {str(e)}")
            else:
                warnings.append("No DKIM signature found")

            # Determine if phishing
            is_phishing = bool(phishing_indicators)
            
            details = (
                f"Phishing Indicators: {', '.join(phishing_indicators) if phishing_indicators else 'None'}; "
                f"Observations: {', '.join(warnings) if warnings else 'None'}"
            )

            logger.info(f"Analysis complete - Is Phishing: {is_phishing}")

            # Save analysis to database
            analysis = PDFAnalysis(
                file_name=pdf_file.name, 
                is_phishing=is_phishing, 
                details=details
            )
            analysis.save()

            # Generate PDF URL
            pdf_url = f"/api/serve-pdf/{pdf_file.name}/"

            response_data = {
                "is_phishing": is_phishing,
                "details": details,
                "phishing_urls": phishing_urls,
                "pdf_url": pdf_url
            }

            logger.info("Returning analysis response")
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error analyzing PDF: {str(e)}", exc_info=True)
            return Response(
                {"error": f"Failed to analyze PDF: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Note: Not deleting the file immediately so it can be viewed
        # You may want to set up a cleanup task to delete old files

class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        logger.info("Received registration request: %s", request.data)
        serializer = RegisterSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            logger.info("User created successfully: %s", request.data.get('username', 'unknown'))
            return Response(
                {"message": "User created successfully. Please check your email to verify your account."},
                status=status.HTTP_201_CREATED
            )
        logger.error("Validation errors: %s", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.profile.is_verified = True
            user.profile.save()
            return Response({"message": "Email verified successfully. You can now log in."}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid verification link."}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = request.user.profile
        return Response({
            'username': request.user.username,
            'email': request.user.email,
            'phone_number': profile.phone_number,
            'is_verified': profile.is_verified,
        })

    def put(self, request):
        profile = request.user.profile
        phone_number = request.data.get('phone_number')
        if phone_number is not None:
            profile.phone_number = phone_number
            profile.save()
            return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)
        return Response({"error": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        profile = request.user.profile
        phone_number = request.data.get('phone_number')
        if phone_number is not None:
            profile.phone_number = phone_number
            profile.save()
            return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)
        return Response({"error": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
    

@method_decorator(csrf_exempt, name='dispatch')
class ServePDFView(View):
    # No permission_classes - allow anyone to view PDFs
    
    def get(self, request, filename):
        file_path = os.path.join(settings.MEDIA_ROOT, 'temp_pdfs', filename)
        
        if not os.path.exists(file_path):
            logger.error(f"PDF not found: {file_path}")
            return HttpResponse("File not found", status=404)
        
        try:
            file_size = os.path.getsize(file_path)
            range_header = request.META.get('HTTP_RANGE', None)
            
            logger.info(f"Serving PDF: {filename}, Size: {file_size}, Range: {range_header}")
            
            # Handle range requests (required for PDF streaming)
            if range_header:
                range_match = re.match(r'bytes=(\d+)-(\d*)', range_header)
                if range_match:
                    start = int(range_match.group(1))
                    end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
                    
                    if start >= file_size:
                        return HttpResponse(status=416)  # Range Not Satisfiable
                    
                    with open(file_path, 'rb') as f:
                        f.seek(start)
                        chunk_size = end - start + 1
                        data = f.read(chunk_size)
                    
                    response = HttpResponse(data, content_type='application/pdf', status=206)
                    response['Content-Range'] = f'bytes {start}-{end}/{file_size}'
                    response['Content-Length'] = str(chunk_size)
                else:
                    # Invalid range
                    response = FileResponse(open(file_path, 'rb'), content_type='application/pdf')
                    response['Content-Length'] = str(file_size)
            else:
                # No range request - send entire file
                response = FileResponse(open(file_path, 'rb'), content_type='application/pdf')
                response['Content-Length'] = str(file_size)
            
            # Add CORS headers
            response['Access-Control-Allow-Origin'] = '*'  # Allow all origins for testing
            response['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Range, Content-Type, Authorization'
            response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Accept-Ranges'
            
            # Enable byte-range requests
            response['Accept-Ranges'] = 'bytes'
            
            # Remove frame restrictions
            response['X-Frame-Options'] = 'ALLOWALL'
            
            # Cache control
            response['Cache-Control'] = 'public, max-age=3600'
            
            return response
            
        except Exception as e:
            logger.error(f"Error serving PDF: {str(e)}", exc_info=True)
            return HttpResponse(f"Error serving file: {str(e)}", status=500)
    
    def head(self, request, filename):
        """Handle HEAD requests for PDF metadata"""
        file_path = os.path.join(settings.MEDIA_ROOT, 'temp_pdfs', filename)
        
        if not os.path.exists(file_path):
            return HttpResponse(status=404)
        
        file_size = os.path.getsize(file_path)
        response = HttpResponse(content_type='application/pdf')
        response['Content-Length'] = str(file_size)
        response['Accept-Ranges'] = 'bytes'
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Range, Content-Type, Authorization'
        response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Accept-Ranges'
        response['X-Frame-Options'] = 'ALLOWALL'
        
        return response
    
    def options(self, request, filename):
        """Handle preflight CORS requests"""
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Range, Content-Type, Authorization'
        response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Accept-Ranges'
        response['Access-Control-Max-Age'] = '86400'
        response['Accept-Ranges'] = 'bytes'
        response['X-Frame-Options'] = 'ALLOWALL'
        
        return response
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes, Navigate, Link as RouterLink } from 'react-router-dom';

import Login from './Login';
import SignUp from './SignUp';
import Profile from './Profile';
import ProtectedRoute from './ProtectedRoute';
import theme from './theme';

import {
    ThemeProvider,
    Container,
    Typography,
    Button,
    Box,
    Paper,
    Alert,
    List,
    ListItem,
    ListItemText,
    AppBar,
    Toolbar,
    IconButton,
    CircularProgress,
} from '@mui/material';
import LogoutIcon from '@mui/icons-material/Logout';

// Backend API URL - uses environment variable or defaults to production
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://phishing-detection-application.onrender.com';

function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [file, setFile] = useState(null);
    const [result, setResult] = useState(null);
    const [pdfError, setPdfError] = useState(null);
    const [uploading, setUploading] = useState(false);
    const interceptorSetup = useRef(false);

    // Check localStorage for tokens on mount
    useEffect(() => {
        const accessToken = localStorage.getItem('access_token');
        const refreshToken = localStorage.getItem('refresh_token');
        if (accessToken && refreshToken) {
            setIsAuthenticated(true);
        }
    }, []);

    // Setup axios interceptors once
    useEffect(() => {
        if (interceptorSetup.current) return;
        interceptorSetup.current = true;

        // Request interceptor
        const requestInterceptor = axios.interceptors.request.use(
            (config) => {
                const token = localStorage.getItem('access_token');
                if (token) {
                    config.headers.Authorization = `Bearer ${token}`;
                }
                return config;
            },
            (error) => Promise.reject(error)
        );

        // Response interceptor for 401 errors
        const responseInterceptor = axios.interceptors.response.use(
            (response) => response,
            async (error) => {
                const originalRequest = error.config;
                
                if (error.response?.status === 401 && !originalRequest._retry) {
                    originalRequest._retry = true;
                    
                    const refreshToken = localStorage.getItem('refresh_token');
                    if (!refreshToken) {
                        handleLogout();
                        return Promise.reject(error);
                    }

                    try {
                        const response = await axios.post(`${API_BASE_URL}/api/token/refresh/`, {
                            refresh: refreshToken,
                        });
                        const { access } = response.data;
                        localStorage.setItem('access_token', access);
                        
                        // Retry original request with new token
                        originalRequest.headers.Authorization = `Bearer ${access}`;
                        return axios(originalRequest);
                    } catch (refreshErr) {
                        handleLogout();
                        return Promise.reject(refreshErr);
                    }
                }
                return Promise.reject(error);
            }
        );

        // Cleanup function
        return () => {
            axios.interceptors.request.eject(requestInterceptor);
            axios.interceptors.response.eject(responseInterceptor);
        };
    }, []);

    const handleUpload = async () => {
        setPdfError(null);
        setResult(null);
        setUploading(true);
        
        if (!file) {
            setPdfError('Please select a PDF file first.');
            setUploading(false);
            return;
        }

        const formData = new FormData();
        formData.append('pdf', file);

        try {
            console.log('Uploading file:', file.name);
            const response = await axios.post(`${API_BASE_URL}/api/analyze-pdf/`, formData, {
                headers: { 
                    'Content-Type': 'multipart/form-data',
                },
            });
            console.log('Analysis response:', response.data);
            console.log('PDF URL:', `${API_BASE_URL}${response.data.pdf_url}`);
            setResult(response.data);
        } catch (error) {
            console.error("Error uploading file:", error);
            const errorMsg = error.response?.data?.error || 
                           error.response?.data?.detail || 
                           'Failed to analyze PDF. Please try again.';
            setPdfError(errorMsg);
        } finally {
            setUploading(false);
        }
    };

    const handleLogout = () => {
        setIsAuthenticated(false);
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        delete axios.defaults.headers.common['Authorization'];
    };

    // Detector Component (PDF Analysis page)
    const Detector = () => (
        <>
            <AppBar position="static">
                <Toolbar>
                    <Typography variant="h6" sx={{ flexGrow: 1 }}>
                        Phishing Detector
                    </Typography>
                    <Button color="inherit" component={RouterLink} to="/profile">
                        Profile
                    </Button>
                    <IconButton color="inherit" onClick={handleLogout}>
                        <LogoutIcon />
                        <Typography variant="body1" sx={{ ml: 1 }}>
                            Logout
                        </Typography>
                    </IconButton>
                </Toolbar>
            </AppBar>
            <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
                <Paper elevation={3} sx={{ p: 4 }}>
                    <Typography variant="h4" gutterBottom align="center">
                        Upload a PDF to Analyze
                    </Typography>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
                            <input
                                type="file"
                                accept=".pdf"
                                onChange={(e) => {
                                    setFile(e.target.files[0]);
                                    setResult(null);
                                    setPdfError(null);
                                }}
                                style={{ display: 'none' }}
                                id="file-upload"
                            />
                            <label htmlFor="file-upload">
                                <Button variant="contained" component="span" disabled={uploading}>
                                    Choose PDF
                                </Button>
                            </label>
                            <Button
                                variant="contained"
                                color="primary"
                                onClick={handleUpload}
                                disabled={!file || uploading}
                                sx={{ ml: 2 }}
                            >
                                {uploading ? <CircularProgress size={24} /> : 'Analyze PDF'}
                            </Button>
                        </Box>
                        {file && (
                            <Typography variant="body2" color="text.secondary">
                                Selected: {file.name}
                            </Typography>
                        )}
                        {pdfError && !result && (
                            <Alert severity="error" sx={{ width: '100%', mt: 2 }}>
                                {pdfError}
                            </Alert>
                        )}
                    </Box>

                    {result && (
                        <Box>
                            <Typography variant="h5" gutterBottom>
                                Uploaded PDF
                            </Typography>
                            <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
                                <Button
                                    variant="contained"
                                    color="primary"
                                    href={`${API_BASE_URL}${result.pdf_url}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Open PDF in New Tab
                                </Button>
                                <Button
                                    variant="outlined"
                                    color="primary"
                                    href={`${API_BASE_URL}${result.pdf_url}`}
                                    download
                                >
                                    Download PDF
                                </Button>
                            </Box>
                            <Paper elevation={1} sx={{ p: 2, mb: 3 }}>
                                {pdfError ? (
                                    <Alert severity="error">{pdfError}</Alert>
                                ) : (
                                    <Box sx={{ position: 'relative', width: '100%', height: '600px' }}>
                                        <iframe
                                            src={`${API_BASE_URL}${result.pdf_url}`}
                                            width="100%"
                                            height="100%"
                                            title="PDF Viewer"
                                            style={{ 
                                                border: '1px solid #ddd',
                                                borderRadius: '4px'
                                            }}
                                            onLoad={() => {
                                                console.log('PDF loaded successfully');
                                            }}
                                            onError={(e) => {
                                                console.error('PDF load error:', e);
                                                setPdfError('Unable to display PDF in browser. Please use the "Open PDF in New Tab" button above.');
                                            }}
                                        />
                                    </Box>
                                )}
                            </Paper>

                            <Typography 
                                variant="h5" 
                                gutterBottom
                                sx={{ 
                                    color: result.is_phishing ? 'error.main' : 'success.main',
                                    fontWeight: 'bold'
                                }}
                            >
                                Analysis Result: {result.is_phishing ? "⚠️ Phishing Detected" : "✓ Safe"}
                            </Typography>
                            
                            {result.details.split("; ").map((section, index) => {
                                const [title, content] = section.split(": ");
                                return (
                                    <Box key={index} sx={{ mb: 2 }}>
                                        <Typography variant="h6" sx={{ fontWeight: 'bold', mt: 2 }}>
                                            {title}
                                        </Typography>
                                        <Paper elevation={1} sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
                                            <List dense>
                                                {content.split(", ").map((item, i) => (
                                                    <ListItem key={i}>
                                                        <ListItemText 
                                                            primary={item}
                                                            primaryTypographyProps={{
                                                                sx: { fontSize: '0.95rem' }
                                                            }}
                                                        />
                                                    </ListItem>
                                                ))}
                                            </List>
                                        </Paper>
                                    </Box>
                                );
                            })}
                            
                            {result.phishing_urls && result.phishing_urls.length > 0 && (
                                <Box sx={{ mt: 3 }}>
                                    <Alert severity="warning" sx={{ mb: 2 }}>
                                        <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                                            ⚠️ Detected Phishing URLs
                                        </Typography>
                                    </Alert>
                                    <Paper elevation={1} sx={{ p: 2, backgroundColor: '#fff3cd' }}>
                                        <List>
                                            {result.phishing_urls.map((url, index) => (
                                                <ListItem key={index}>
                                                    <ListItemText 
                                                        primary={url}
                                                        primaryTypographyProps={{
                                                            sx: { 
                                                                wordBreak: 'break-all',
                                                                color: 'error.main',
                                                                fontFamily: 'monospace'
                                                            }
                                                        }}
                                                    />
                                                </ListItem>
                                            ))}
                                        </List>
                                    </Paper>
                                </Box>
                            )}
                        </Box>
                    )}
                </Paper>
            </Container>
        </>
    );

    return (
        <ThemeProvider theme={theme}>
            <Router>
                <Routes>
                    <Route
                        path="/login"
                        element={<Login setIsAuthenticated={setIsAuthenticated} />}
                    />
                    <Route path="/signup" element={<SignUp />} />
                    <Route
                        path="/app"
                        element={
                            <ProtectedRoute isAuthenticated={isAuthenticated}>
                                <Detector handleLogout={handleLogout} />
                            </ProtectedRoute>
                        }
                    />
                    <Route
                        path="/profile"
                        element={
                            <ProtectedRoute isAuthenticated={isAuthenticated}>
                                <Profile handleLogout={handleLogout} />
                            </ProtectedRoute>
                        }
                    />
                    <Route path="/" element={<Navigate to="/login" />} />
                </Routes>
            </Router>
        </ThemeProvider>
    );
}

export default App;
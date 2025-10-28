import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import {
    Container,
    Paper,
    Typography,
    TextField,
    Button,
    Box,
    Alert,
} from '@mui/material';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';

function Profile({ handleLogout }) {
    const [profile, setProfile] = useState(null);
    const [phoneNumber, setPhoneNumber] = useState('');
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchProfile = async () => {
            const accessToken = localStorage.getItem('access_token');
            const refreshToken = localStorage.getItem('refresh_token');

            // If no tokens, don't try to fetch - let ProtectedRoute handle redirect
            if (!accessToken || !refreshToken) {
                setLoading(false);
                return;
            }

            try {
                // Set the authorization header
                const response = await axios.get('http://localhost:8000/api/user-profile/', {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    }
                });
                setProfile(response.data);
                setPhoneNumber(response.data.phone_number);
                setError(null);
            } catch (err) {
                // If token expired, try to refresh
                if (err.response?.status === 401) {
                    try {
                        const { data } = await axios.post('http://localhost:8000/api/token/refresh/', {
                            refresh: refreshToken,
                        });
                        localStorage.setItem('access_token', data.access);

                        // Retry fetching profile with new token
                        const retryResponse = await axios.get('http://localhost:8000/api/user-profile/', {
                            headers: {
                                'Authorization': `Bearer ${data.access}`
                            }
                        });
                        setProfile(retryResponse.data);
                        setPhoneNumber(retryResponse.data.phone_number);
                        setError(null);
                    } catch (refreshErr) {
                        // Refresh failed → logout
                        console.error('Token refresh failed:', refreshErr);
                        handleLogout();
                        navigate('/login');
                    }
                } else {
                    setError('Failed to load profile.');
                    console.error('Profile fetch error:', err);
                }
            } finally {
                setLoading(false);
            }
        };

        fetchProfile();
    }, [navigate, handleLogout]);

    const handleUpdate = async () => {
        const accessToken = localStorage.getItem('access_token');
        
        try {
            await axios.put('http://localhost:8000/api/user-profile/', 
                { phone_number: phoneNumber },
                {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    }
                }
            );
            setSuccess('Profile updated successfully.');
            setError(null);
        } catch (err) {
            if (err.response?.status === 401) {
                // Token expired during update
                handleLogout();
                navigate('/login');
            } else {
                setError('Failed to update profile.');
                setSuccess(null);
            }
        }
    };

    if (loading) {
        return (
            <Container maxWidth="sm" sx={{ mt: 4, mb: 4 }}>
                <Typography align="center">Loading...</Typography>
            </Container>
        );
    }

    if (!profile) {
        return (
            <Container maxWidth="sm" sx={{ mt: 4, mb: 4 }}>
                <Alert severity="error">Failed to load profile. Please try logging in again.</Alert>
            </Container>
        );
    }

    return (
        <Container maxWidth="sm" sx={{ mt: 4, mb: 4 }}>
            <Paper elevation={3} sx={{ p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <AccountCircleIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
                <Typography variant="h5" gutterBottom>
                    User Profile
                </Typography>
                {error && (
                    <Alert severity="error" sx={{ width: '100%', mb: 2 }}>
                        {error}
                    </Alert>
                )}
                {success && (
                    <Alert severity="success" sx={{ width: '100%', mb: 2 }}>
                        {success}
                    </Alert>
                )}
                <Box sx={{ width: '100%' }}>
                    <TextField
                        label="Username"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={profile.username}
                        disabled
                    />
                    <TextField
                        label="Email"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={profile.email}
                        disabled
                    />
                    <TextField
                        label="Phone Number"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                    />
                    <Button
                        variant="contained"
                        color="primary"
                        fullWidth
                        sx={{ mt: 2, py: 1.5 }}
                        onClick={handleUpdate}
                    >
                        Update Profile
                    </Button>
                    <Button
                        variant="outlined"
                        color="secondary"
                        fullWidth
                        sx={{ mt: 2, py: 1.5 }}
                        onClick={handleLogout}
                    >
                        Logout
                    </Button>
                </Box>
            </Paper>
        </Container>
    );
}

export default Profile;
import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import {
    Container,
    Paper,
    Typography,
    TextField,
    Button,
    Alert,
    Box,
} from '@mui/material';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';

// Backend API URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://phishing-detection-application.onrender.com';

function Login({ setIsAuthenticated }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const response = await axios.post(`${API_BASE_URL}/api/token/`, {
                username,
                password,
            });
            
            console.log('Login response:', response.data); // Debug log
            
            const { access, refresh } = response.data;

            // Store tokens in localStorage
            localStorage.setItem('access_token', access);
            localStorage.setItem('refresh_token', refresh);
            
            // Set authorization header for future requests
            axios.defaults.headers.common['Authorization'] = `Bearer ${access}`;
            
            // Update authentication state
            setIsAuthenticated(true);

            // Navigate to app
            navigate('/app');
        } catch (err) {
            console.error('Login error:', err); // Debug log
            
            const errorMsg = err.response?.data?.detail || 
                             err.response?.data?.non_field_errors?.[0] || 
                             err.response?.data?.message ||
                             'Invalid username or password';
            setError(errorMsg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Container maxWidth="xs" sx={{ mt: 8 }}>
            <Paper elevation={3} sx={{ p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <LockOutlinedIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
                <Typography variant="h5" gutterBottom>
                    Sign In
                </Typography>
                {error && (
                    <Alert severity="error" sx={{ width: '100%', mb: 2 }}>
                        {error}
                    </Alert>
                )}
                <Box component="form" onSubmit={handleLogin} sx={{ width: '100%' }}>
                    <TextField
                        label="Username"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        autoComplete="username"
                    />
                    <TextField
                        label="Password"
                        type="password"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        autoComplete="current-password"
                    />
                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        fullWidth
                        sx={{ mt: 2, py: 1.5 }}
                        disabled={loading}
                    >
                        {loading ? 'Signing In...' : 'Sign In'}
                    </Button>
                </Box>
                <Typography variant="body2" sx={{ mt: 2 }}>
                    Don't have an account?{' '}
                    <Link to="/signup" style={{ color: '#1976d2', textDecoration: 'none' }}>
                        Sign Up
                    </Link>
                </Typography>
            </Paper>
        </Container>
    );
}

export default Login;
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
import PersonAddIcon from '@mui/icons-material/PersonAdd';

// Backend API URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://phishing-detection-application.onrender.com';

function SignUp() {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [password2, setPassword2] = useState('');
    const [phoneNumber, setPhoneNumber] = useState('');
    const [errors, setErrors] = useState({});

    const navigate = useNavigate();

    const handleSignUp = async (e) => {
        e.preventDefault();
        setErrors({});
        if (password !== password2) {
            setErrors({ password: 'Passwords do not match' });
            return;
        }
        try {
            await axios.post(`${API_BASE_URL}/api/register/`, {
                username,
                email,
                password,
                password2,
                phone_number: phoneNumber,
            });
            navigate('/login');
        } catch (err) {
            if (err.response && err.response.data) {
                setErrors(err.response.data);
            } else {
                setErrors({ non_field_errors: 'Registration failed. Please try again.' });
            }
        }
    };

    return (
        <Container maxWidth="xs" sx={{ mt: 8 }}>
            <Paper elevation={3} sx={{ p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <PersonAddIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
                <Typography variant="h5" gutterBottom>
                    Sign Up
                </Typography>
                {errors.non_field_errors && (
                    <Alert severity="error" sx={{ width: '100%', mb: 2 }}>
                        {errors.non_field_errors}
                    </Alert>
                )}
                <Box component="form" onSubmit={handleSignUp} sx={{ width: '100%' }}>
                    <TextField
                        label="Username"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        error={!!errors.username}
                        helperText={errors.username}
                    />
                    <TextField
                        label="Email"
                        type="email"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        error={!!errors.email}
                        helperText={errors.email}
                    />
                    <TextField
                        label="Phone Number"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        placeholder="e.g., +1234567890"
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
                        error={!!errors.password}
                        helperText={errors.password}
                    />
                    <TextField
                        label="Confirm Password"
                        type="password"
                        variant="outlined"
                        fullWidth
                        margin="normal"
                        value={password2}
                        onChange={(e) => setPassword2(e.target.value)}
                        required
                        error={!!errors.password}
                        helperText={errors.password}
                    />
                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        fullWidth
                        sx={{ mt: 2, py: 1.5 }}
                    >
                        Sign Up
                    </Button>
                </Box>
                <Typography variant="body2" sx={{ mt: 2 }}>
                    Already have an account?{' '}
                    <Link to="/login" style={{ color: '#1976d2', textDecoration: 'none' }}>
                        Sign In
                    </Link>
                </Typography>
            </Paper>
        </Container>
    );
}

export default SignUp;
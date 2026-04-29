/* ══════════════════════════════════════════════════
   api.js — Configuración central del frontend
   
   Todo el frontend habla con Node.js a través de aquí.
   Node.js es el que habla con Firebase (el frontend NO).
══════════════════════════════════════════════════ */

export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

/**
 * Función helper para hacer peticiones al backend Node.js.
 * Automáticamente agrega el token JWT si el usuario tiene sesión.
 */
export const apiFetch = async (endpoint, options = {}) => {
    const token = localStorage.getItem('vento_token');

    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...(options.headers || {}),
    };

    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers,
    });

    return response;
};

/**
 * Guardar sesión del usuario (token JWT + datos)
 */
export const saveSession = (token, user) => {
    localStorage.setItem('vento_token', token);
    localStorage.setItem('vento_user', JSON.stringify(user));
};

/**
 * Cerrar sesión
 */
export const clearSession = () => {
    localStorage.removeItem('vento_token');
    localStorage.removeItem('vento_user');
};

/**
 * Obtener usuario de la sesión actual
 */
export const getSession = () => {
    const user = localStorage.getItem('vento_user');
    return user ? JSON.parse(user) : null;
};

// Google Client ID (configurar en Firebase Console → Auth → Google → Web client ID)
export const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

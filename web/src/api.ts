/**
 * API client for communicating with the FastAPI backend.
 * All crypto operations go through this layer.
 */
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

export async function apiPost<T>(path: string, data: unknown): Promise<T> {
  const response = await api.post<T>(path, data);
  return response.data;
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await api.get<T>(path);
  return response.data;
}

export default api;

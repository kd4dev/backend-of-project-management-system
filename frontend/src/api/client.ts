import axios from "axios";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Response interceptor for better error handling
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { response } = error;
    const config = error.config as
      | {
          __retryCount?: number;
          method?: string;
          url?: string;
        }
      | undefined;

    // Retry logic for network errors on idempotent requests
    if (!response && config && config.method === "get") {
      const retryCount = config.__retryCount || 0;
      if (retryCount < 1) {
        config.__retryCount = retryCount + 1;
        await new Promise((resolve) => setTimeout(resolve, 500));
        return apiClient(config);
      }
    }

    // Handle session expiry
    if (response?.status === 401) {
      const authEndpoints = ["/auth/login", "/auth/register", "/auth/forgot-password", "/auth/reset-password", "/auth/verify-email", "/auth/refresh-token"];
      const shouldDispatch = !authEndpoints.some((endpoint) => config?.url?.includes(endpoint));
      if (shouldDispatch) {
        window.dispatchEvent(new CustomEvent("auth:unauthorized"));
      }
    }

    // Enhance error messages
    if (response?.data?.message) {
      error.message = response.data.message;
    } else {
      // Generic friendly messages based on status code
      switch (response?.status) {
        case 400:
          error.message = 'Invalid request. Please check your input.';
          break;
        case 403:
          error.message = "You don't have permission to perform this action.";
          break;
        case 404:
          error.message = 'The requested resource was not found.';
          break;
        case 500:
          error.message = 'Server error. Please try again later.';
          break;
        default:
          if (!error.message) {
            error.message = 'An unexpected error occurred. Please try again.';
          }
      }
    }

    return Promise.reject(error);
  }
);

export default apiClient;

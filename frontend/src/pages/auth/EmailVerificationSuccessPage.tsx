import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckCircle2, XCircle, Loader2 } from "lucide-react";
import apiClient from "@/api/client";

export default function EmailVerificationSuccessPage() {
  const { verificationToken } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const verifyEmail = async () => {
      try {
        const response = await apiClient.get(`/auth/verify-email/${verificationToken}`);
        setStatus("success");
        setMessage(response.data.message || "Email verified successfully!");
      } catch (error: any) {
        setStatus("error");
        setMessage(error.response?.data?.message || "Verification failed. The link may be expired or invalid.");
      }
    };

    if (verificationToken) {
      verifyEmail();
    }
  }, [verificationToken]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-emerald-100 via-white to-sky-100 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 px-4 py-12">
      <Card className="w-full max-w-md border border-slate-200/70 bg-white/90 shadow-xl backdrop-blur dark:border-slate-800 dark:bg-slate-950/80">
        <CardHeader className="text-center space-y-2">
          <div className="mx-auto mb-2 w-16 h-16 rounded-full flex items-center justify-center">
            {status === "loading" && (
              <div className="bg-gray-100 dark:bg-slate-800/60 rounded-full p-3">
                <Loader2 className="w-8 h-8 text-gray-600 dark:text-gray-300 animate-spin" />
              </div>
            )}
            {status === "success" && (
              <div className="bg-emerald-100 dark:bg-emerald-900/30 rounded-full p-3">
                <CheckCircle2 className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
              </div>
            )}
            {status === "error" && (
              <div className="bg-rose-100 dark:bg-rose-900/30 rounded-full p-3">
                <XCircle className="w-8 h-8 text-rose-600 dark:text-rose-400" />
              </div>
            )}
          </div>
          <CardTitle className="text-2xl font-bold">
            {status === "loading" && "Verifying Email..."}
            {status === "success" && "Email Verified!"}
            {status === "error" && "Verification Failed"}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-center text-muted-foreground">{message}</p>

          {status === "success" && (
            <div className="space-y-3">
              <div className="bg-emerald-50 border border-emerald-200 dark:border-emerald-900/40 dark:bg-emerald-900/20 rounded-lg p-4">
                <p className="text-sm text-emerald-800 dark:text-emerald-200">
                  Your account is now active. You can login with your credentials.
                </p>
              </div>
              <Button
                className="w-full"
                onClick={() => navigate("/login")}
              >
                Continue to Login
              </Button>
            </div>
          )}

          {status === "error" && (
            <div className="space-y-3">
              <Button
                variant="outline"
                className="w-full"
                onClick={() => navigate("/register")}
              >
                Back to Registration
              </Button>
              <Button
                className="w-full"
                onClick={() => navigate("/login")}
              >
                Try Login Anyway
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

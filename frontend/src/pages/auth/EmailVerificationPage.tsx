import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Mail, AlertCircle, Loader2 } from "lucide-react";
import apiClient from "@/api/client";
import { toast } from "sonner";

export default function EmailVerificationPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [isResending, setIsResending] = useState(false);
  const email = searchParams.get("email");

  const handleResendVerification = async () => {
    if (!email) {
      toast.error("Please provide an email address to resend verification.");
      return;
    }
    setIsResending(true);
    try {
      await apiClient.post("/auth/resend-email-verification", { email });
      toast.success("Verification email sent! Please check your inbox.");
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to resend verification email");
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-sky-100 via-white to-emerald-50 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 px-4 py-12">
      <Card className="w-full max-w-md border border-slate-200/70 bg-white/90 shadow-xl backdrop-blur dark:border-slate-800 dark:bg-slate-950/80">
        <CardHeader className="text-center space-y-2">
          <div className="mx-auto mb-2 w-16 h-16 bg-sky-100 dark:bg-sky-900/30 rounded-full flex items-center justify-center">
            <Mail className="w-8 h-8 text-sky-600 dark:text-sky-400" />
          </div>
          <CardTitle className="text-2xl font-bold">Verify your email</CardTitle>
          <p className="text-sm text-muted-foreground">
            We sent a verification link to complete your registration.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="text-center space-y-2">
            <p className="text-gray-600">
              We've sent a verification email to:
            </p>
            <p className="font-semibold text-gray-900">
              {email || "your email address"}
            </p>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 space-y-2">
            <div className="flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-1">Next Steps:</p>
                <ol className="list-decimal list-inside space-y-1">
                  <li>Check your email inbox</li>
                  <li>Click the verification link</li>
                  <li>Return here to login</li>
                </ol>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <Button
              variant="outline"
              className="w-full"
              onClick={handleResendVerification}
              disabled={isResending || !email}
            >
              {isResending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Sending...
                </>
              ) : (
                "Resend Verification Email"
              )}
            </Button>

            <Button
              variant="default"
              className="w-full"
              onClick={() => navigate("/login")}
            >
              Go to Login
            </Button>
          </div>

          <div className="text-center text-sm text-gray-500">
            <p>Didn't receive the email? Check your spam folder.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

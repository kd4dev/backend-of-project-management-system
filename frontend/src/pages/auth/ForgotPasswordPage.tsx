import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import apiClient from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { useState } from "react";
import { handleApiError } from "@/lib/handleApiError";
import { Loader2 } from "lucide-react";

const formSchema = z.object({
  email: z.string().email(),
});

export default function ForgotPasswordPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [isSent, setIsSent] = useState(false);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: "",
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true);
    try {
      await apiClient.post("/auth/forgot-password", values);
      setIsSent(true);
      toast.success("Reset link sent to your email");
    } catch (error: any) {
      handleApiError(error, form.setError);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-100 via-white to-sky-100 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 px-4 py-12">
      <Card className="w-full max-w-md border border-slate-200/70 bg-white/90 shadow-xl backdrop-blur dark:border-slate-800 dark:bg-slate-950/80">
        <CardHeader className="text-center space-y-2">
          <CardTitle className="text-2xl font-bold">Reset your password</CardTitle>
          <p className="text-sm text-muted-foreground">We'll email you a secure reset link.</p>
        </CardHeader>
        <CardContent className="space-y-6">
          {isSent ? (
               <div className="text-center space-y-4">
                   <p className="text-emerald-600">
                       If an account exists with that email, we have sent a password reset link.
                   </p>
                   <Link to="/login">
                       <Button variant="outline" className="w-full">Back to Login</Button>
                   </Link>
               </div>
          ) : (
            <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                    <FormItem>
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                        <Input placeholder="email@example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                    )}
                />
                <Button type="submit" className="w-full" disabled={isLoading}>
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Sending...
                      </>
                    ) : (
                      "Send Reset Link"
                    )}
                </Button>
                </form>
            </Form>
          )}
          
          {!isSent && (
              <div className="mt-4 text-center text-sm">
                <Link to="/login" className="text-blue-600 hover:underline">
                Back to Login
                </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

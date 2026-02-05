import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Link, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { handleApiError } from "@/lib/handleApiError";
import { PASSWORD_REGEX, PASSWORD_REQUIREMENTS_MESSAGE } from "@/lib/passwordRules";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

const formSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  email: z.string().email("Please enter a valid email"),
  password: z
    .string()
    .regex(PASSWORD_REGEX, PASSWORD_REQUIREMENTS_MESSAGE),
});

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    try {
      await register(values);
      toast.success("Registration successful! Check your inbox to verify your email.");
      // PRD: Redirect to email verification page, not dashboard
      navigate(`/verify-email?email=${encodeURIComponent(values.email)}`);
    } catch (error) {
      const errorCode = (error as any)?.response?.data?.errorCode;
      if (errorCode === "DUPLICATE_EMAIL") {
        form.setError("email", { message: "An account with this email already exists." });
      }
      if (errorCode === "DUPLICATE_USERNAME") {
        form.setError("username", { message: "This username is already taken." });
      }
      handleApiError(error, form.setError);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-amber-100 via-white to-sky-100 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 px-4 py-12">
      <Card className="w-full max-w-md border border-slate-200/70 bg-white/90 shadow-xl backdrop-blur dark:border-slate-800 dark:bg-slate-950/80">
        <CardHeader className="space-y-2 text-center">
          <CardTitle className="text-3xl font-semibold">Create your account</CardTitle>
          <p className="text-sm text-muted-foreground">
            Get started with a secure, verified workspace.
          </p>
        </CardHeader>
        <CardContent className="space-y-6">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input placeholder="username" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
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
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="******" {...field} />
                    </FormControl>
                    <FormDescription>{PASSWORD_REQUIREMENTS_MESSAGE}</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button
                type="submit"
                className="w-full"
                disabled={form.formState.isSubmitting}
              >
                {form.formState.isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Creating account...
                  </>
                ) : (
                  "Register"
                )}
              </Button>
            </form>
          </Form>
          <div className="text-center text-sm">
            Already have an account?{" "}
            <Link to="/login" className="font-medium text-sky-600 hover:underline">
              Login
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

import { toast } from "sonner";
import type { FieldValues, UseFormSetError } from "react-hook-form";

export function handleApiError<TFieldValues extends FieldValues>(
  error: any,
  setError?: UseFormSetError<TFieldValues>,
) {
  const responseData = error?.response?.data;
  const serverErrors = responseData?.errors;

  if (Array.isArray(serverErrors) && setError) {
    serverErrors.forEach((item: { field?: string; message?: string }) => {
      if (item?.field) {
        setError(item.field as keyof TFieldValues, {
          type: "server",
          message: item.message || "Invalid value",
        });
      }
    });
  }

  const message =
    responseData?.message || error?.message || "Something went wrong";
  toast.error(message);
}

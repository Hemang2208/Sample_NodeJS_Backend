export type ErrorData = {
  message: string;
  error: string;
  details?: unknown;
};

export const createError = (
  statusCode: number,
  message: string,
  error: string,
  details?: unknown
): ErrorData => ({
  message,
  error,
  ...(details !== undefined && { details }),
});

export const isAppError = (error: unknown): error is ErrorData => {
  return (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    "error" in error
  );
};

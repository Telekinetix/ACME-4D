# Compiler_Variables

Declares the process-level variables used by the `ON ERR CALL` error handler across the `tk-acme` component.

This method is invisible and runs at compile time only. All other variables in the component are declared locally at point of use.

## Variables Declared

| Variable | Type | Used by |
|----------|------|---------|
| `vl_acmeHttpError` | Integer | `ACME_HTTP_Error` — captures 4D error number on HTTP failure |
| `vt_acmeHttpError` | Text | `ACME_HTTP_Error` — captures error description string |

## Notes

These variables must be process-level (not local `var`) because they are set inside the `ACME_HTTP_Error` error-handler method and read by the calling method immediately after `ON ERR CALL("")`. Local variables in `ACME_HTTP_Error` would be invisible to the calling stack frame.

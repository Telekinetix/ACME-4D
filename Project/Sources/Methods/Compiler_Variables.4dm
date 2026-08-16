//%attributes = {"invisible":true}
// ----------------------------------------------------
// Method: Compiler_Variables
// Process-level variable declarations for the ACME component.
// Required by 4D's typed-syntax compiler; kept in one place for
// discoverability. Only process-level error-trap variables live here —
// every other variable is declared locally at point of use.
// ----------------------------------------------------
C_LONGINT(vl_acmeHttpError)
C_TEXT(vt_acmeHttpError)

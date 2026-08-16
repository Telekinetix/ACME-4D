// ----------------------------------------------------
// Class: ACMELogger
// Structured, secret-safe logging for the ACME component.
//
// Rules enforced here:
//   • Private keys, account keys, and challenge tokens are NEVER logged,
//     even at DEBUG level. Callers must not pass them in messages.
//   • Log entries are objects with: timestamp, level, component, message,
//     and an optional context object (safe fields only).
//
// Log levels (numeric, ascending verbosity):
//   0 = ERROR   — failures requiring attention
//   1 = WARN    — recoverable issues or unexpected-but-handled states
//   2 = INFO    — normal lifecycle events (account registered, cert issued…)
//   3 = DEBUG   — detailed flow tracing (for development / Pebble testing)
//
// Destination:
//   By default, entries are appended to the 4D log (LOG EVENT) at INFO+ and
//   stored in an in-process log collection for the host to query via status().
//   Set logToFile to redirect to a dedicated text log file.
// ----------------------------------------------------

property _logLevel : Integer
property _entries : Collection
property _maxEntries : Integer
property logToFile : Boolean
property logFilePath : Text

// Level constants
property ERROR : Integer
property WARN : Integer
property INFO : Integer
property DEBUG : Integer


Class constructor($logLevel : Integer)

	This.ERROR:=0
	This.WARN:=1
	This.INFO:=2
	This.DEBUG:=3

	This._logLevel:=(Count parameters>=1) ? $logLevel : This.INFO
	This._entries:=New collection
	This._maxEntries:=500  // ring-buffer cap; oldest entries dropped when full
	This.logToFile:=False
	This.logFilePath:=""


// ============================================================
// LEVEL SETTERS
// ============================================================

Function setLevel($level : Integer) : cs.acme.ACMELogger
	This._logLevel:=$level
	return This


// ============================================================
// LOG METHODS
// ============================================================

Function error($message : Text; $context : Object)
	This._log(This.ERROR; "ERROR"; $message; $context)


Function warn($message : Text; $context : Object)
	This._log(This.WARN; "WARN"; $message; $context)


Function info($message : Text; $context : Object)
	This._log(This.INFO; "INFO"; $message; $context)


Function debug($message : Text; $context : Object)
	This._log(This.DEBUG; "DEBUG"; $message; $context)


// ============================================================
// QUERY
// ============================================================

Function entries() : Collection
	// Return a copy of the current in-memory log entries.
	return This._entries.copy()


Function lastEntries($count : Integer) : Collection
	// Return the most recent $count log entries.
	var $start : Integer
	$start:=This._entries.length-$count
	If ($start<0)
		$start:=0
	End if
	return This._entries.slice($start)


Function clearEntries()
	This._entries:=New collection


// ============================================================
// INTERNAL
// ============================================================

Function _log($numLevel : Integer; $levelLabel : Text; $message : Text; $context : Object)
	If ($numLevel>This._logLevel)
		return
	End if

	var $entry : Object
	$entry:=New object(\
		"timestamp"; String(Current date; ISO date; Current time); \
		"level"; $levelLabel; \
		"component"; "acme"; \
		"message"; $message)

	If ($context#Null)
		$entry.context:=$context
	End if

	// Ring-buffer: drop oldest when at capacity
	If (This._entries.length>=This._maxEntries)
		This._entries.shift()
	End if
	This._entries.push($entry)

	// Emit to 4D event log at INFO and above (not DEBUG — too noisy in production)
	If ($numLevel<=This.INFO)
		LOG EVENT(Into current log file; "[acme] "+$levelLabel+": "+$message; wInformation)
	End if

	// Optional file sink
	If (This.logToFile) && (Length(This.logFilePath)>0)
		var $vf : 4D.File
		var $vt_line : Text
		$vf:=File(This.logFilePath)
		$vt_line:=JSON Stringify($entry)+Char(10)
		Try
			$vf.setText($vt_line; "utf-8"; File append)
		Catch
			// Swallow file write errors — don't let logging kill the cert renewal
		End try
	End if

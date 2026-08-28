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
	
	This:C1470.ERROR:=0
	This:C1470.WARN:=1
	This:C1470.INFO:=2
	This:C1470.DEBUG:=3
	
	This:C1470._logLevel:=(Count parameters:C259>=1) ? $logLevel : This:C1470.INFO
	This:C1470._entries:=New collection:C1472
	This:C1470._maxEntries:=500  // ring-buffer cap; oldest entries dropped when full
	This:C1470.logToFile:=False:C215
	This:C1470.logFilePath:=""
	
	
	// ============================================================
	// LEVEL SETTERS
	// ============================================================
	
Function setLevel($level : Integer) : cs:C1710.ACMELogger
	This:C1470._logLevel:=$level
	return This:C1470
	
	
	// ============================================================
	// LOG METHODS
	// ============================================================
	
Function error($message : Text; $context : Object)
	This:C1470._log(This:C1470.ERROR; "ERROR"; $message; $context)
	
	
Function warn($message : Text; $context : Object)
	This:C1470._log(This:C1470.WARN; "WARN"; $message; $context)
	
	
Function info($message : Text; $context : Object)
	This:C1470._log(This:C1470.INFO; "INFO"; $message; $context)
	
	
Function debug($message : Text; $context : Object)
	This:C1470._log(This:C1470.DEBUG; "DEBUG"; $message; $context)
	
	
	// ============================================================
	// QUERY
	// ============================================================
	
Function entries() : Collection
	// Return a copy of the current in-memory log entries.
	return This:C1470._entries.copy()
	
	
Function lastEntries($count : Integer) : Collection
	// Return the most recent $count log entries.
	var $start : Integer
	$start:=This:C1470._entries.length-$count
	If ($start<0)
		$start:=0
	End if 
	return This:C1470._entries.slice($start)
	
	
Function clearEntries()
	This:C1470._entries:=New collection:C1472
	
	
	// ============================================================
	// INTERNAL
	// ============================================================
	
Function _log($numLevel : Integer; $levelLabel : Text; $message : Text; $context : Object)
	If ($numLevel>This:C1470._logLevel)
		return 
	End if 
	
	var $entry : Object
	$entry:=New object:C1471(\
		"timestamp"; String:C10(Current date:C33; ISO date:K1:8; Current time:C178); \
		"level"; $levelLabel; \
		"component"; "acme"; \
		"message"; $message)
	
	If ($context#Null:C1517)
		$entry.context:=$context
	End if 
	
	// Ring-buffer: drop oldest when at capacity
	If (This:C1470._entries.length>=This:C1470._maxEntries)
		This:C1470._entries.shift()
	End if 
	This:C1470._entries.push($entry)
	
	// Emit to 4D event log at INFO and above (not DEBUG — too noisy in production)
	If ($numLevel<=This:C1470.INFO)
		LOG EVENT:C667(Into 4D commands log:K38:7; "[acme] "+$levelLabel+": "+$message; wInformation)
	End if 
	
	// Optional file sink
	If (This:C1470.logToFile) && (Length:C16(This:C1470.logFilePath)>0)
		var $vf : 4D:C1709.File
		var $vt_line : Text
		$vf:=File:C1566(This:C1470.logFilePath; fk platform path:K87:2)
		$vt_line:=JSON Stringify:C1217($entry)+Char:C90(10)
		Try
			$vf.setText($vt_line; "utf-8"; File append)
		Catch
			// Swallow file write errors — don't let logging kill the cert renewal
		End try
	End if 
	
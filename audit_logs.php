<?php
header('Content-Type: application/json');

// Connect to the database (use your connection settings)
$mysqli = new mysqli("localhost", "root", "", "audit_db");

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// Fetch audit logs
$sql = "SELECT id, user_id, action, timestamp FROM audit_logs";
$result = $mysqli->query($sql);

$audit_logs = array();
while ($row = $result->fetch_assoc()) {
    $audit_logs[] = $row;
}

// Return the audit logs in JSON format
echo json_encode($audit_logs);

$mysqli->close();
?>

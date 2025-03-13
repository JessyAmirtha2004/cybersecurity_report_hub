<?php
if(!defined('host')) define('host',"localhost");
if(!defined('username')) define('username',"root");
if(!defined('password')) define('password',"");
if(!defined('db_tbl')) define('db_tbl',"audit_trailing");

Class DBConnection{
    public $conn;
    function __construct(){
        $this->conn = new mysqli(host,username,password,db_tbl);
        if(!$this->conn){
            die("Database Connection Error. ".$this->conn->error);
        }
    }
    function __destruct(){
         $this->conn->close();
    }
}

$db = new DBConnection();
$conn= $db->conn;
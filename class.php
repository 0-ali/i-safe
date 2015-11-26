<?php
error_reporting(0);
/**
 * I-Safe CLASS ;
 *
 * @author Mohamed Ali Musa - (XC0d3rZ);
 * @since  2015-16-07;
 * @version  3.0;
 * @modified 00-00-00;
 * @copyright 2013 - 2015 XC0d3rZ;
 * @githup https://github.com/x-c0d3rz;
 * @facebook https://fb.com/mr.face.king;
 * @website -----;
 **/

/**
 * @Config
 **/
include "Inc/config.php";
class iSafe 
{

#################################
# I Safe - Settings  Selection  #
#################################

Var $Trytimes;
#NO_COMMENT
Var $Requesttimes;
#REQUEST NUMBERS ON ACTIVE SESSION 
Var $Blocking;
#BLOCK TIME IF VISTER DOING UNLEGAL THINGS
Var $SmartyClass = "Inc/Smarty/Smarty.class.php"; 

######################################
# I Safe - Database Connecting Info  #
######################################

Var $db;
#Database Name
Var $db_host;
#Database Host
Var $db_user;
#Database User Name
Var $db_pass;
#Database Password

################################
# I Safe - Functions Selection #
################################

/**
 * Connecting To Database;
 *
 * @param $debug = false;
 **/
Private Function Databases($debug = true)
{
Global $config;	
$this->db      = $config['iSafe']['databases']['db_name'];	
$this->db_host = $config['iSafe']['databases']['db_host'];	
$this->db_user = $config['iSafe']['databases']['db_user'];	
$this->db_pass = $config['iSafe']['databases']['db_pass'];	
MYSQL_CONNECT(
$this->db_host,
$this->db_user,
$this->db_pass
)Or die 
(
$this->debug(1, __LINE__ , __FILE__)
);
MYSQL_SELECT_DB(
$this->db
)Or die 
(
$this->debug(2, __LINE__ , __FILE__)
);

}

/**
 * Templates Engine ;
 *
 **/
Private Function Smarty($client=false,$tpl,$assigns='none')
{
Global $config;		
require_once "".$this->SmartyClass.""; 
$Smarty = new Smarty ;
if($client==true):
$title = md5(rand(10,10000000000000000));
$Smarty->assign("title",$title);
$Smarty->assign("url",$config['iSafe']['generals']['url']);
$Smarty->assign("client",$config['iSafe']['generals']['client']);
$Smarty->assign("msg",$config['iSafe']['generals']['msg']);
if($assigns!='none'){
foreach ($assigns as $key => $val) {
$Smarty->assign($key,$val);
}

}
endif;
$Smarty->display("Style/".$tpl);
}

/**
 * Debug Output;
 *
 * @param $bug = bug title or bug number;
 * @notice 
 * Error Numbers,
 * 1 For Database Connect 
 * 2 For Database Select 
 **/
Private Function debug($bug,$line,$file)
{
Global $config;
$title = md5(rand(10,10000000000000000));
$client = $config['iSafe']['generals']['client'] ;
$logs = file_get_contents("Inc/logs.txt");
switch ($bug) {
		case '1':
			$assigns= array("bug" => ''.$this->Phras('db_connect_error').'');
            $this->Smarty(true,"debug.tpl",$assigns);
            file_put_contents("Inc/logs.txt", $logs."\n"."Bug :  ".$this->Phras('db_connect_error').", ID Bug : ".$title." , Date : ".date('F j,Y - H:i:s')." , Location : ".$file." At Line (".$line.")  , Client ID :".$client);
            exit();
        	break;
		case '2':
			$assigns= array("bug" => ''.$this->Phras('db_select_error').'');
            $this->Smarty(true,"debug.tpl",$assigns);
            file_put_contents("Inc/logs.txt", $logs."\n"."Bug :  ".$this->Phras('db_select_error').", ID Bug : ".$title." , Date : ".date('F j,Y - H:i:s')." , Location : ".$file." At Line (".$line.")  , Client ID :".$client);
            exit();
			break;
		
			default:
			$assigns= array("bug" => ''.$bug.'');
            $this->Smarty(true,"debug.tpl",$assigns);
            file_put_contents("Inc/logs.txt", $logs."\n"."Bug :  ".$bug.", ID Bug : ".$title." , Date : ".date('F j,Y - H:i:s')." , Location : ". $file ." At Line (".$line.")  , Client ID :".$client);
            exit();
			break;
	}	

}

/**
 * I-Safe Phrases ;
 *
 * @param $param = phras;
 **/
Private Function Phras($param)
{
Global $config;
$lang = $config['iSafe']['generals']['language'];	

if($lang == "ar")
{	
$Phras = array();
$Phras['db_connect_error'] = "خطأ اثناء الاتصال بقاعدة البيانات";
$Phras['db_select_error'] = "لم يتم تحديد قاعدة بيانات صالحة";
}
else
{
include "Inc/Language/".$lang."xml";

}
if(!empty($Phras[$param])){
return $Phras[$param];
}
else
{
return $param;
}	

}
/**
 * I-Safe Get IP ;
 *
 **/

Private Function IP()
{
if(!empty($_SERVER['HTTP_CLIENT_IP']))
{
$ip = $_SERVER['HTTP_CLIENT_IP'];
}
else if(!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
{
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}else{
$ip = $_SERVER['REMOTE_ADDR'];
}
return $ip;
}
/**
 * I-Safe Band IP;
 *
 * @param $logs => IF = 1 logs will save on databases , IF = 2 logs will save on txt file - set this value from config file 
 * @param $type => IF = 1 will band ip by ht-access file and band will be for ever , IF = 2 will band ip by session and band will be for 1 hour   
 **/
Public Function IP_Band($type,$i=false) // this function 
{
Global $config;

$logs = $config['iSafe']['generals']['logs']; // logs type 
$ip = (empty($i)) ? $this->IP() : $i ;
$date = date("h:i:s").'-'.date("F j, Y");
// SQL QUERYS - Go Away Please 
if($logs=='db')
{
$this->Databases();	
$INSERT = "INSERT INTO `bands_logs` (`id`, `ip`, `status`, `date`, `times`) VALUES 
(
NULL, 
'".$ip."', 
'UNLEGAL WORK', 
'".$date."',
'1'
)";
$query = mysql_query("SELECT * FROM bands_logs WHERE ip = '$ip' ");
while($Rows = mysql_fetch_array($query)){

$Row_ip = $Rows['ip'];

$Row_times = $Rows['times'];

$times = 1;

$plus  = $times+$Row_times;
}
if($Row_ip==$ip)
{
mysql_query("UPDATE  bands_logs SET  times = '".$plus."' , date = '".$date."' WHERE  ip ='".$ip."' LIMIT 1 ");
}
else
{
mysql_query($INSERT);
}	
}
else
{
$txt_data = "###########  IP : ".$ip. "  Date:".$date.  ".   Location : ".$this->URLS().". Datas : ".$this->QUERYS()." #######";    
$this->logs(2,'Logs/bands.txt',$txt_data);
}

if($type==1 OR  $type==2 )
{
$htaccess = file_get_contents($config['iSafe']['generals']['htaccess'])Or die($this->debug($this->Phras('cannot_htaccess_file'),__LINE__,__FILE__));
$data_htaccess  = $htaccess."\n"."
#####################################################
# Script:  I-Safe - IP BAND.                        
# Version: 1.0\n#####################################################  
Deny from ".$ip."
# Data : ".$date."
# Location : ".$this->URLS()." 
#####################################################
"; 
if(!stristr($htaccess, "Deny from ".$ip."")){
file_put_contents($config['iSafe']['generals']['htaccess'], $data_htaccess)Or die($this->debug($this->Phras('cannot_write_htaccess_file'),__LINE__,__FILE__));
}

}


}

/**
 * I-Safe Logs ;
 *
 * @param $type => IF = 1 using db to save logs , IF = 2 using txt file to save logs
 * @param $file => logs file name 
 * @param $data => logs data
 **/

Public Function logs($type,$file,$data)
{
Global $config;    
$old_data = file_get_contents($file)Or die($this->debug($this->Phras('cannot_logs_file'),__LINE__,__FILE__));
$datas = $old_data."\n".$data;
switch ($type) {
	case '1':
		break;
	case '2':
	file_put_contents($file, $datas)Or die($this->debug($this->Phras('cannot_write_logs_file'),__LINE__,__FILE__));		
			break;	
	
	default:
		return false;
		break;
}


}

/**
 * I-Safe Make Safe ;
 *
 * @Copyright : Programmed By : Mustafa Taj , Many Thanks . , Edited By : Xc0d3r.
 *    
 **/

Public Function mksafe($txt, $intval = false, $no_html = false, $no_nl2br = true) // 
    {

        $txt = trim($txt);
        if ($no_html == true):
            $txt = htmlspecialchars($txt);
        endif;
 
        if ($no_nl2br == false) 
        {
            $txt = str_replace("\r\n", "<br />", $txt);
            $txt = str_replace("&#13;&#10;", "<br />", $txt);
        }
        $txt = mysql_real_escape_string($txt);
        $preg_find = array('#^javascript#i', '#^vbscript#i');
        $preg_replace = array('java script', 'vb script');
        $txt = str_replace('<meta', '', $txt);
        $txt = preg_replace('#(<[^>]+[\s\r\n\"\'])(on|xmlns)[^>]*>#iU', "$1>", $txt);
        $txt = preg_replace('#</*(\?xml|applet|meta|xml|blink|link|style|script|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base)[^>]*>#i', "", $txt);
        $txt = preg_replace($preg_find, $preg_replace, $txt);
        $txt = str_replace("select", "s elect", $txt);
        $txt = str_replace("update", "u pdate", $txt);
        $txt = str_replace("delete", "d elete", $txt);
        $txt = str_replace("union", "u nion", $txt);
        $txt = str_replace("drop", "d rop", $txt);
        $txt = str_replace("tr_", "", $txt);
        $txt = str_replace("*", "", $txt);

        if ($intval == true)
        {
            $txt = intval($txt);
        }
      
     
        return $txt;
    }


Private Function QUERYS()
{
if(!empty($_SERVER["QUERY_STRING"]))
{
$query =$_SERVER["QUERY_STRING"];
}
elseif(!empty($_SERVER['HTTP_X_REQUESTED_WITH']))
{
$query =$_SERVER['HTTP_X_REQUESTED_WITH'];
}
else
{
$query ='empty'; 
}
return $this->mksafe($query);
}

Private Function URLS(){
$current_page_uri = $_SERVER['REQUEST_URI'];
$part_url = explode("/", $current_page_uri);
$url_name = $current_page_uri;
if(!empty($url_name)){
$url = $url_name;
}elseif(empty($url_name)){
$url = 'empty';
}
return $this->mksafe(urldecode($url));
}
Public Function Monitoring($save_on) // Monitoring 
{
Global $config;
// variables ==>
$http_ref     = $_SERVER['HTTP_REFERER'];
$request_sche = $_SERVER['REQUEST_SCHEME'];
$request_time = $_SERVER['REQUEST_TIME'];
$user_agent   = $_SERVER['HTTP_USER_AGENT'];
$post_vars    = file_get_contents('php://input');
$http_accept  = $_SERVER['HTTP_ACCEPT'];
$time          = date("h:i:s").'-'.date("F j, Y");
$save_on = 'db';
if($save_on=='db')
{
$this->Databases();

// Checking  insert logs to db 
$Query_Check = "  
remote_ip= '".$this->mksafe($this->IP())."' 
AND  
request_uri= '".$this->URLS()."' 
AND 
user_agent= '".$this->mksafe($user_agent)."'
AND
post_vars= '".$this->mksafe($post_vars)."'
AND
query_string= '".$this->QUERYS()."'
";  
$Rows_Query = mysql_query("SELECT *  FROM `monitoring` WHERE ".$Query_Check." limit 1");
if (mysql_num_rows(Rows_Query) > 0) {
mysql_query("UPDATE `monitoring` SET
seen_times = $se,
last_vist  = '$time'
WHERE ".$Query_Check."
");	
}
else
{
mysql_query("INSERT INTO `monitoring` (`id`, `remote_ip`, `request_uri`, `http_ref`, `query_string`, `request_time`, `user_agent`, `request_scheme`, `post_vars`, `seen_times`, `first_vist`, `last_vist`, `accept`, `is_safe`) VALUES 
(
NULL, 
'".$this->mksafe($this->IP())."',
'".$this->URLS()."',
'".$this->mksafe($http_ref)."',
'".$this->QUERYS()."',
'".$request_time."',
'".$this->mksafe($user_agent)."',
'".$this->mksafe($request_sche)."',
'".$this->mksafe($post_vars)."',
'1',
'".$time."',
'null',
'".$this->mksafe($http_accept)."',
'yet'
)
");
} // Checking Query :) Research 
$this->SMART_RESEARCH(); // my son
}}
/**
 * I-Safe Vulnerabilities Research bot  ;
 *
**/
Private Function SMART_RESEARCH()
{	
$this->Databases();	
$Query = "SELECT `post_vars`,`query_string`,`request_uri`,`user_agent` FROM monitoring";
$SQL_Query = mysql_query($Query);
Function Updates($where){ return " UPDATE `monitoring` SET `is_safe` = 'Yes' WHERE ".$where." "; }
Function Where($data,$type){if($type==1){$where = 'post_vars'; }elseif($type==2){$where = 'query_string'; }elseif($type==3){$where = 'request_uri'; }elseif($type==4){$where = 'user_agent'; } return $where."='".$data."'";  } 
while($Research = mysql_fetch_array($SQL_Query)) {
$Checking = array();	
$Checking[1]    = $Research['post_vars'];
$Checking[2]    = $Research['query_string'];
$Checking[3]    = $Research['request_uri']; 
$Checking[4]    = $Research['user_agent'];
////////////////////////////////////////////
$ip_addr = $Research['remote_ip'];
for ($i=1; $i <5 ; $i++) { 	
    // checking all this
if(preg_match("/'|<$string>|<>|<|>|order by|union|select|version|from|group_concat|information_schema|where|0x3a|union|select|insert|drop|delete|update|cast|create|char|convert|alter|declare|order|script|set|md5|benchmark|encodexml|applet|meta|xml|blink|link|style|script|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base'/",strtolower($Checking[$i]))){
mysql_query(Updates(Where($Checking[$i],$i)));
$this->IP_Band(1,$ip_addr);
}  

}

}

} 



}

$iSafe = new iSafe;

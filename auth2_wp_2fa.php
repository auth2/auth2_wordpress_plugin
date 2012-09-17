<?php

/*
    Plugin Name: INA Securety Auth2 Two-Factor Authentication
    Version: 1.0.0
    Author: INA Security
    Author URI: http://auth2.com/plugins/wordpress/
    License: GNU AFFERO GENERAL PUBLIC LICENSE v3

    This file is part of INA Securety Auth2 Two-Factor Authentication wordpress plugin or Auth2WPTFA in short.

    Auth2WPTFA (the plugin) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your option) 
    any later version.

    Auth2WPTFA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
    See the GNU Affero General Public License for more details.

    You should have received a copy of the GNU General Public License along with Auth2WPTFA.
    If not, see <http://www.gnu.org/licenses/>.
*/

function guid()
{
     if (function_exists('com_create_guid'))
     {
         return com_create_guid();
     }
     else
     {
         mt_srand((double)microtime()*10000);
         $charid = strtoupper(md5(uniqid(rand(), true)));
         $hyphen = chr(45);// "-"
         $uuid = chr(123)// "{"
                 .substr($charid, 0, 8).$hyphen
                 .substr($charid, 8, 4).$hyphen
                 .substr($charid,12, 4).$hyphen
                 .substr($charid,16, 4).$hyphen
                 .substr($charid,20,12)
                 .chr(125);// "}"
         return $uuid;
     }
 }


function TOTP($key, $time, $pin_len)
{
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)
    $msg = str_pad($time, 16, '0',STR_PAD_LEFT);
    
    $mgs_b = pack("H*",$msg);

    $hash = hash_hmac('sha1', $mgs_b, $key, true);
    $offset = ord($hash[strlen($hash)-1]) & 0xF;

    $b1=((ord($hash[$offset])&0x7f)<<24);
    $b2=((ord($hash[$offset+1])&0xff)<<16);
    $b3=((ord($hash[$offset+2])&0xff)<<8);
    $b4=((ord($hash[$offset+3])&0xff));

    $bPIN= ($b1 | $b2 | $b3 | $b4)%pow(10,$pin_len) ;
    return str_pad($bPIN, $pin_len, '0', STR_PAD_LEFT);
}

function base32decode($b32str) 
{
	$b32LookupTable = array(
	    'A' => 0,  'B' => 1,  'C' => 2,  'D' => 3,  'E' => 4,  'F' => 5, 'G' => 6, 'H' => 7,
	    'I' => 8,  'J' => 9,  'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14,'P' => 15, 
	    'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23, 
	    'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30,'7' => 31
	);

    $b32str = strtoupper($b32str);
    $length = strlen($b32str);
    $n = 0;
    $b = 0;
    $decoded = null;
    for ($i = 0; $i < $length; $i++) 
    {
        $n = $n << 5;
        $n = $n + $b32LookupTable[$b32str[$i]];
        $b = $b + 5;

        if ($b >= 8) 
        {
            $b = $b - 8;
            $decoded .= chr(($n & (0xFF << $b)) >> $b);
        }
    }
    return $decoded;
}

function auth2_authenticate_user($user="", $username="", $password="") 
{
    if (isset($_POST["auth2_2fa"]) && isset($_POST["username"]))
    {        
        $key = trim($_POST['key']);            
        $username = $_POST['username'];
        $user = get_userdatabylogin($username);
        $token_name = $_POST['token_name'];
        
        remove_action("authenticate", "wp_authenticate_username_password");
        
        if($user)
        {
            $token_value = get_user_option($token_name, $user->ID );                        
            $user_key_b32 = get_user_option("auth2_totp_key", $user->ID );
            
            $user_key = base32decode($user_key_b32);                       

            $token_value = get_option($token_name);
            $token_name_parts = explode("|",$token_name);
            $create_time = $token_name_parts[0];
            $current_time = time();
            $diff = $current_time - $create_time;
            
            delete_option($token_name);
            
            if($token_value != $user->ID  || $diff <0 || $diff > 300)
            {
               return  new WP_Error("auth2_authentication_failed", __("<strong>ERROR</strong>: Auth2: Authentication failed. Time expired."));
            }
                       
            $time = floor(microtime(true)/30);
            $key_expected =  TOTP($user_key, ($time), 6);
            $key_expected1 =  TOTP($user_key, ($time-1), 6);
            $key_expected2 =  TOTP($user_key, ($time+1), 6);
            
            			
            if(strlen($key)>=2 && ($key == $key_expected || $key == $key_expected1 || $key == $key_expected2))
            {                
            	//TODO: check if the key was used earlier
            	
                wp_set_auth_cookie($user->ID);
                wp_safe_redirect($_POST['redirect_to']);
                exit();
            }
            else
            {
                return  new WP_Error("auth2_authentication_failed", __("<strong>ERROR</strong>: Auth2: Authentication failed. Invalid User or PIN."));
            }
        }
        else
        {
            return  new WP_Error("auth2_authentication_failed", __("<strong>ERROR</strong>: Auth2: Authentication failed. Invalid User or PIN."));
        }
    }

    if(strlen($username)>0) 
    {
        $user = get_userdatabylogin($username);

        if (!$user)
        {
            return;
        }

        $usr = new WP_User($user->ID);

        global $wp_roles;
        foreach ($wp_roles->get_names() as $r)
        {
            $all_roles[strtolower(before_last_bar($r))] = ucfirst(before_last_bar($r));
        }

		$auth2_enable_2fa = get_user_option("auth2_enable_2fa", $user->ID );
        $user_key_b32 = get_user_option("auth2_totp_key", $user->ID);
        
        if($auth2_enable_2fa != "true" || strlen($user_key_b32) < 5)
        {
			return;
        }

        //We do not want the default processing after this point.
        remove_action("authenticate", "wp_authenticate_username_password");
    
        if (wp_check_password($password, $user->user_pass, $user->ID))
        {
            $create_time = time();
            $token_name = $create_time. "|". trim(guid());
            $token_value=$user->ID;
            update_option($token_name, $token_value);        
            auth2_sign_request($user, $token_name, $_POST['redirect_to']);
            exit();
        } 
        else 
        {
            return new WP_Error("auth2_authentication_failed", __("<strong>ERROR</strong>: Invalid username or incorrect password."));
        }
    }
}

function auth2_sign_request($user, $token_name, $redirect) {
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" dir="ltr" lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title><?php echo get_bloginfo('name'); ?>&rsaquo; Log In</title>
    <?php
        global $wp_version;
        if(version_compare($wp_version, "3.3", "<="))
        {
        ?>
        <link rel="stylesheet" type="text/css" href="<?php echo admin_url("css/login.css?ver=$wp_version"); ?>" />
        <?php
        }
        else
        {
        ?>
        <link rel="stylesheet" type="text/css" href="<?php echo admin_url("css/wp-admin.css?ver=$wp_version"); ?>" />
        <link rel="stylesheet" type="text/css" href="<?php echo admin_url("css/colors-fresh.css?ver=$wp_version"); ?>" />
        <?php
        }
        ?>
</head>

<body class="login">
    <div id="login">
        <h1><a href="http://wordpress.org/" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a></h1>
            <form method="POST"  id="auth2_form" action="wp-login.php">                        
                <label for="key"><a href="http://auth2.com">Auth2</a> Key<br />
                <input type="hidden" name="auth2_2fa" value="true" />
                <input type="text" name="key" id="key" /></label>            
                <input type="hidden" name="username" value="<?php echo esc_attr($user->user_login); ?>"/>
                <input type="hidden" name="token_name" value="<?php echo esc_attr($token_name); ?>"/>
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>"/>                
                <input type="submit" value="Login" class="button-primary"  tabindex="100"/>                        
            </form>
    </div>
                
    <script type="text/javascript">
        function wp_attempt_focus(){
        setTimeout( function(){ try{
        d = document.getElementById('key');
        d.focus();
        d.select();
        } catch(e){}
        }, 200);
        }
            
        wp_attempt_focus();
        if(typeof wpOnload=='function')wpOnload();
    </script>            
</body>
</html>
<?php
}

function auth2_user_setting($user)
{
?>
   <tr>
   		<th scope="row">Autht2 2FA</th>
        <td><label for="auth2_enable_2fa">
        <input name="auth2_enable_2fa" type="checkbox" value="true" <?php if($user->auth2_enable_2fa) echo 'checked="checked"'; echo "class='$user->auth2_enable_2fa'"; ?> /> Enable Auth2 two-factor authentication
        <a href="http://auth2.com/plugins/wordpress/help/">More information</a> 
        </label></td>
    </tr>

    <tr>
        <th scope="row">Autht2 2FA Key</th>
        <td><label for="auth2_totp_key">
        <input name="auth2_totp_key" type="text" id="auth2_totp_key" maxlength="40" size="50" value="<?php echo $user->auth2_totp_key; ?>"/>
        <input type="button" onclick="auth2_generate()" value="Generate" /><br />
        <span id="auth2_update_message" style="color:red"></span><br />
        <img id="auth2_qr_code_img" src="https://chart.googleapis.com/chart?cht=qr&chs=150x150&chld=H|0&chl=<?php echo $user->auth2_totp_key; ?>" alt="QR Code" height="150" width="150" />
        </label></td>
   </tr>      
<?php
}

function auth2_user_setting_head_script() 
{
?>
	<script language="javascript" type="text/javascript">
	
		function auth2_generate_secret(len)
		{
			var b32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
			var secret = "";
			var i;
			for(i=0;i<len;i++)
			{    
			    randomnumber=Math.floor(Math.random()*32);
			    secret +=(b32alphabet[randomnumber]);
			}
			
			return secret;
		}
		function auth2_generate()
		{
			var secret = auth2_generate_secret(16);
			
			var textbox = document.getElementById('auth2_totp_key');
			textbox.value = secret;		
			
			
			
			var message_label = document.getElementById('auth2_update_message');					
            message_label.innerHTML = "You must update your profile now to save the new key and update your mobile apps as well.";

			var google_qr_url = "https://chart.googleapis.com/chart?cht=qr&chs=150x150&chld=H|0&chl="+secret;
			var qr_code_img = document.getElementById('auth2_qr_code_img');					
			qr_code_img.src = google_qr_url;
		}
				
	</script>
<?php
}

function auth2_save_user_setting($user_id) 
{
    $auth2_enable_2fa = $_POST["auth2_enable_2fa"];
    $auth2_totp_key = $_POST["auth2_totp_key"];

    update_usermeta( $user_id, "auth2_enable_2fa", $auth2_enable_2fa);
    update_usermeta( $user_id, "auth2_totp_key", $auth2_totp_key);
}

add_action('personal_options', 'auth2_user_setting');
add_action('personal_options_update', 'auth2_save_user_setting');
add_action('admin_head', 'auth2_user_setting_head_script');
add_filter('authenticate', 'auth2_authenticate_user', 10, 3);
?>

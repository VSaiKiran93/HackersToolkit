
$(document).ready(function() {
  $('#scan-form').submit(function(event) {
    event.preventDefault();
    
    // Get input values
    var type =$("input[name='radio']:checked").val();
    var formData,url;
    if(type=="nmap"){
        formData = {
        'ip_address': $('#ip-address').val(),
        'scan_type': $('#scan-type').val(),
          }
          url="http://127.0.0.1:8080/"
    }else{
        formData = {
        'ip_address': $('#ip-address').val(),
        //'port_range': $('#port-range').val(),
          }
          url="http://127.0.0.1:8000/"
    }
   
    fetch(url, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
                })
                
                .then(response => response.json())
                .then(response => {

                    console.log("response data"+response)
                    $("#output-text").val(JSON.stringify(response));
                
                 })

  });
});

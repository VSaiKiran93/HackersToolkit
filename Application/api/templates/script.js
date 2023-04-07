$(document).ready(function() {
  $('#scan-form').submit(function(event) {
    event.preventDefault();
    console.log("sdfdfsdfdsfdsdfsfsdfsdfsddfs")
    // Get input values
    var formData = {
	'ip_address': $('#input-text').val(),
	'scan_type': $('#scan-type').val(),
    }


    fetch("http://192.168.0.141:8000/nmap-scan/", {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
                })
                
                .then(response => response.json())
                .then(response => {

                  console.log("testdcfdsfdvf"+response)
                    $("#output-text").val(JSON.stringify(response));
                
                 })

    

  });
});

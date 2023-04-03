$(document).ready(function() {
  $('#nmap-form').submit(function(event) {
    event.preventDefault();

    // Get input values
    var formData = {
	'ip_address': $('#ip-address').val(),
	'port_range': $('#port-range').val(),
	'scan_type': $('#scan-type').val(),
    }


    // send AJAX request to API endpoint
    $.ajax({
      type: 'POST',
      url: 'http://127.0.0.1:8000/',
      data: JSON.stringify(formData),
      contentType: 'application/json',
      success: function(data) {
        // Display scan results in container element
        $console.log('Scan-results:', data);
        $('#scan-result').html(data);
      },
      error: function(xhr, status, error) {
        alert('Error retrieving scan results.');
      }
    });
  });
});

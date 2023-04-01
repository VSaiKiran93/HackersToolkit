$(document).ready(function() {
  $('#nmap-form').submit(function(event) {
    event.preventDefault();

    // Get input values
    var ipAddress = $('#ip-address').val();
    var portRange = $('#port-range').val();
    var scanType = $('#scan-type').val();


    // send AJAX request to API endpoint
    $.ajax({
      url: '/api/nmap-scan/',
      type: 'POST',
      data: {
        'ip_address': ipAddress,
        'port_range': portRange,
        'scan_type': scanType
      },
      success: function(data) {
        // Display scan results
        $('#scan-results').html(data);
      },
      error: function() {
        alert('Error retrieving scan results.');
      }
    });
  });
});

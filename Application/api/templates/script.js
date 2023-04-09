$(document).ready(function() {
  $("#submit-button").click(function(event) {
    event.preventDefault();
    var ipAddress = $("#input-text").val();
    var scanType = $("#scan-type").val();
    var scannerType = $("input[name='radio']:checked").val();
    $.ajax({
      type: "POST",
      url: "http://74.235.154.69:8000/",
      data: JSON.stringify({
        ipAddress: ipAddress,
        scanType: scanType,
        scannerType: scannerType
      }),
      contentType: "application/json",
      success: function(response) {
        $("#output-text").val(response);
      }
    });
  });
});


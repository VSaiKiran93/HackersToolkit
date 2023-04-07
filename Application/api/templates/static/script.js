$(document).ready(function() {
  $("#submit-button").click(function(event) {
    event.preventDefault();
    var ipAddress = $("#input-text").val();
    var scanType = $("#scan-type").val();
    var scannerType = $("input[name='radio']:checked").val();
    $.ajax({
      type: "POST",
      url: "/nmap-scan/post",
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


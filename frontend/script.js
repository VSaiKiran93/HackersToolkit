$(document).ready(function() {
  $('input:radio[name="radio"]').change(
    function(){
        if ($(this).is(':checked') && $(this).val() == 'Nikto') {
            // append goes here
            $('#scantypeId').css('display', 'none');
            $('#scan-type').val('');
            $('#ip-address').val('');

        }
        if ($(this).is(':checked') && $(this).val() == 'nmap') {
          // append goes here
          $('#scantypeId').css('display', 'block');
          $('#scan-type').val('Quick Scan');
          $('#ip-address').val('');
      }
    });
  $('#scan-form').submit(function(event) {
    event.preventDefault();
    // Get input values
    var method_type = "";
    var type =$("input[name='radio']:checked").val();
    var url;
    if(type=="nmap"){
        let obj = {
        'ip': $('#ip-address').val(),
        'scan_type': $('#scan-type').val(),
          }
          url="http://127.0.0.1:8000/";
          method_type = 'POST';
    $("#output-text").val("");        
    fetch(url, {
      method: method_type,
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify(obj)
    } )
    .then(response => response.json())
    .then(response => {
        console.log("response data"+response)
        $("#output-text").val(JSON.stringify(response));
    
     })
    }else{
      createTarget()
    }
});
function createTarget(){
    let ip_address= $('#ip-address').val(),
      url='http://127.0.0.1:8000/create-target/'+ip_address+"/";
      method_type = 'GET';
      $("#output-text").val("");               
    fetch(url, {
    method: method_type,
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
  } )
  .then(response => response.json())
  .then(response => {
    if(response && response.target_id){
      console.log("create Target response data"+response?.target_id);
      createTask(ip_address,response.target_id)
    }
  })
}
function createTask(ip_address,target_id){
      url='http://127.0.0.1:8000/create-task/'+ip_address+'/'+target_id+'/';
      method_type = 'GET';
      $("#output-text").val("");               
fetch(url, {
  method: method_type,
  headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
  },
} )
.then(response => response.json())
.then(response => {
  if(response && response.task_id){
    console.log("create task response data"+response.task_id);
    startTask(response.task_id)
  }
 })
}

function startTask(taskid){
      url='http://127.0.0.1:8000/start-scan/'+taskid+"/";
      method_type = 'GET';
      $("#output-text").val("");               
fetch(url, {
  method: method_type,
  headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
  },
} )
.then(response => response.json())
.then(response => {
  if(response && response.report_id){
    console.log("start task response data"+response.report_id);
    getReport(response.report_id)
  }
 })
}

function getReport(reportid){
      url='http://127.0.0.1:8000/get-report/'+reportid+"/";
      method_type = 'GET';
      $("#output-text").val("");               
fetch(url, {
  method: method_type,
  headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
  },
} )
.then(response => response?.json())
.then(response => {
    console.log("get response data"+response)
    $("#output-text").val(JSON.stringify(response));

 })
}
});

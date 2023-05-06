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
    var spinner = new Spinner().spin();
    var loaderContainer = document.querySelector('#loader-container');
    //loaderContainer.appendChild(spinner.el);
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
          url="http://20.51.254.106:8000/";
          method_type = 'POST';
    $("#output-text").val("");   
    loaderContainer.appendChild(spinner.el);     
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
     .finally(() => {
      loaderContainer.removeChild(spinner.el);
     });
    }else{
      createTarget()
    }
});
function createTarget(){
    let ip_address= $('#ip-address').val(),
      url='http://20.51.254.106:8000/create-target/'+ip_address+"/";
      method_type = 'GET';
      $("#output-text").val("");     
      loaderContainer.appendChild(spinner.el);          
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
  .finally(() => {
    loaderContainer.removeChild(spinner.el);
   });
}
function createTask(ip_address,target_id){
      url='http://20.51.254.106:8000/create-task/'+ip_address+'/'+target_id+'/';
      method_type = 'GET';
      $("#output-text").val("");      
      loaderContainer.appendChild(spinner.el);         
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
 .finally(() => {
  loaderContainer.removeChild(spinner.el);
 });
}

function startTask(taskid){
      url='http://20.51.254.106:8000/start-scan/'+taskid+"/";
      method_type = 'GET';
      $("#output-text").val(""); 
      loaderContainer.appendChild(spinner.el);              
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
 .finally(() => {
  loaderContainer.removeChild(spinner.el);
 });
}

function getReport(reportid){
      url='http://20.51.254.106:8000/get-report/'+reportid+"/";
      method_type = 'GET';
      $("#output-text").val("");  
      loaderContainer.appendChild(spinner.el);             
fetch(url, {
  method: method_type,
  headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
  },
} )
.then(response => response.blob())

  .then(blob => {
      const reader = new FileReader();
      reader.readAsArrayBuffer(blob);
      reader.onloadend = () => {
       const arrayBuffer = reader.result;
       const decoder = new TextDecoder();
       const report = decoder.decode(arrayBuffer);
       //console.log("get response data"+arrayBuffer)
       console.log(report);
       $("#output-text").val(report);
      }

  })
  .finally(() => {
    loaderContainer.removeChild(spinner.el);
   });
}
});

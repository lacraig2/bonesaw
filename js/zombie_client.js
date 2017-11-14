var Browser = require("zombie");
var assert = require("assert");    

// Load the page from localhost
browser = new Browser()
browser.runScripts = true;
browser.visit("http://192.168.7.2", function () {    

  assert.ok(browser.success);
  console.log("made it here");
  // append script tag
  // var injectedScript = browser.document.createElement("script");
  // injectedScript.setAttribute("type","text/javascript");
  // injectedScript.setAttribute("src", "http://code.jquery.com/jquery-1.11.0.min.js");    

  // browser.body.appendChild(injectedScript);    

  // browser.wait(function(window) {
    // make sure the new script tag is inserted
    // return window.document.querySelectorAll("script").length == 4;
  // }, function() {
    // jquery is ready
  // assert.equal(browser.evaluate("$.fn.jquery"), "1.11.0");
  // var b = require('./bonescript');
    console.log(browser.evaluate(`
    // file to be changed
    var file = '/home/debian/out.txt';
    // this is the data read
    let output = '';
    // this is the data to append
    let append = "datatoappend\\n";
    var b = _bonescript; 

    // this function reads file and outputs data in the output variable
    b.readTextFile(file, function (x){
        output = x.data;

        console.log('inside method output of x '+ output);
    });

    // this function writes data to a file
    // this function is delayed so it does not write before read is completed
    setTimeout(function(){ 
         console.log("output of x:  "+output);
        b.writeTextFile(file, output+append, readStatus);
    }, 3000); 

    function readStatus(x) {
        console.log(JSON.stringify(x));
    }

    `));
  // });
});
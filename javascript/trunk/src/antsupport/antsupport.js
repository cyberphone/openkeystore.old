"use strict";
function AntConsole ()
{
}

AntConsole.prototype.debug = function (message)
{
    var echo_task = project.createTask ("echo");
    echo_task.setMessage (message);
    echo_task.perform ();
};

var console = new AntConsole ();





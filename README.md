canhazaxs
=========

A tool for enumerating the attack surface exposed on via the file system on 
an Android device.

It is similar to using find(1) but prioritizes output by potential security 
impact of the exposed end point.

It allows specifying specific users or groups on the command line. If 
specified, these replace or augment the privileges inherited from the parent 
process.

This tool was originally developed while authoring the Android Hacker's Handbook.

NOTE: This tool uses standard APIs and thus could be useful on systems other than Android.


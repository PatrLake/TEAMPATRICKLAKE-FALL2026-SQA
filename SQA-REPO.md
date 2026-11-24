# Project Report

## Confirmation Of Activity Completion

All activities for the project have been completed.

## How To Identify My Implementation

When I created the repo for this project, I decided to keep all of the files from the slikube.zip grouped together in their own folder rather than having them be in the top-level folder of the repo. This means that all of the files not in the slikube folder are part of my implementation. In addition, I also created a file "forensics_logger.py" which is stored alongside the slikube files. I also modified three of the provided files, "graphtaint.py", "parser.py", and "scanner.py", as needed in order to integrate forensics into the ten methods of my choice. My modifications to those three files are clearly labeled.

## How To Replicate My Work

### Setting Up The Repo

My work began with getting the repo set up on GitHub, which I found challenging considering that this is the first repo I've ever created on GitHub. I also needed to install Git on my PC, which I had also never done before, so that I could upload the provided files with a Git command in my local terminal rather than trying to upload the files with my web browser.

### Working On Fuzzing And GitHub Actions

After that, I began working on fuzz.py, the results of which can be seen in the file "fuzz_results.log". The ten methods I selected for fuzzing can be seen listed in the summary of that file, along with the specifications of the bugs found. When fuzzing, I used the fixed seed of "20261122" so that I could later verify when performing the forensics part of the project that my modifications to the ten methods did not result in any changes regarding what bugs the fuzz.py file would find. The seed is needed because the fuzzing inputs are randomly generated.

In the fuzz results, it is worth noting how no bugs were found with two of the selected methods: "scanner.isValidUserName" and "scanner.checkIfValidSecret". These methods are particularly resilient to the fuzzing because their inputs are properly guarded, whereas the rest of the eight methods selected by me tended to not check their inputs much, such as by looking at their types before beginning to process them.

Before pushing fuzz.py to GitHub, I also created the sqa-ci.yml file, which is stored in the .github folder in the top-level folder of the repo. This YML file defines how the fuzzing is implemented with GitHub Actions, and I slightly modified this file later when I was working on the forensics part of the project.

After running fuzz.py locally was successful, I pushed the new files to GitHub and the push pass with green check marks with GitHub Actions as can be seen in the screenshots near the end of this MD file.

### Working On Forensics

I then began working on the forensics part of the project. I decided to use the same ten methods I had used for fuzzing so as to simplify my implementation for this project. A logger for forensics needed to be created, and so forensics_logger.py was born. This PY file is stored alongside the slikube files so that my modified versions of the ten methods can all easily access it.

When modifying the ten methods, there was a problem in that at first, the fuzzing was not returning the same number of crashes as it had been before. I discovered that this was a problem related to how Python was catching exceptions. After changing a couple of the methods in scanner.py from "except Exception as exc" to "except builtins.Exception as exc", the problem was resolved. This trouble was being caused by the "from sarif_om import *" at the top of the file, which was overwriting the built-in reference Python uses for the "Exception" keyword. Note that this problem was something I was working on locally on my laptop and it was never pushed to GitHub.

After this, I slightly modified the YML workflow file so that the fuzzing as well as the forensics would both be involved in the GitHub Actions for the project, and then I pushed the new files to GitHub.

In the screenshots below, you can see the green check marks for the two runs with GitHub Actions as well as a screenshot of my local terminal showing how all of the ten methods contributed to the forensics log.

![Screenshot of GitHub Actions main page](screenshots/GitHub%20Actions%20screenshot%201.png)

![Screenshot of second run of GitHub Actions](screenshots/GitHub%20Actions%20screenshot%202.png)

![Screenshot of additional results of second run](screenshots/GitHub%20Actions%20screenshot%203.png)

![Screenshot of terminal summary of forensics log](screenshots/PowerShell%20screenshot.png)

### Cloning The Repository

You can clone the repo, install the neccessary dependendies (pip install ruamel.yaml pandas numpy sarif-om jschema-to-python), and then run fuzz.py for yourself (python fuzz.py) if you would like to. Doing so will generate the two LOG files for the fuzzing results and the forensics results, which can be inspected as desired.

## What I Learned While Doing This Project

The most important thing I learned while doing this project was how to create and contribute to a GitHub repo and use Git on my laptop to pull and push to it with my local copy of the repo and verify the acceptability of those pushes by using GitHub Actions, since this was my first time doing any of those things. In regards to fuzzing, my biggest takeaway was with how the fuzzer couldn't find even a single error with the two methods that did appropriately guard their inputs, which demonstrates how blindly trusting callers to send correct arguments is exactly what can lead to crashes. In regards to forensics, my biggest takeaway was with how the forensics log ended up being helpful in discovering why my modified versions of the ten methods were not resulting in the same fuzzing results as the original versions, which demonstrated how such logs can truly be useful for identifying hard-to-spot problems with code, such as how the built-in definition of the "Exception" word was being overwritten by sarif_om's definition.
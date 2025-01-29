# Detecting Anomalies with Splunk and Sysmon EventCodes

## Introduction
In this blog post, I’ll share my experience using Splunk to analyze Sysmon EventCodes for detecting anomalies in a real-world scenario. Building on the foundation from the *Windows Event Logs & Finding Evil* module, I explored how Sysmon EventCodes can help identify suspicious activities and potential threats. Here’s a walkthrough of my process, key findings, and lessons learned.

---

## Objective
The goal of this exercise was to:
1. Identify all Sysmon EventCodes present in the dataset.
2. Understand the significance of each EventCode in detecting malicious activity.
3. Perform preliminary queries to spot anomalies, such as unusual parent-child process hierarchies.

---

## Step 1: Identifying Sysmon EventCodes
To begin, I ran the following Splunk query to identify all Sysmon EventCodes in the dataset:

```spl
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
| stats count by ParentImage, Image
| sort - count

![Splunk Query Results](images/splunk-query.png)

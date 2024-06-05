# Device-specific-Behaviros
## Dataset
Dataset -- Package names and hashes for all unpacked apps.

## Device Information
DeviceInformation -- Brand, model and OS information crawled from GSMArena.

## Source Code of Our Tool
SourceCode -- Source code for our tools.

## Rule
rule -- Rules used in rule matching section.

Additionally, we added corresponding comments for each rule class to explain the purpose of device-specific behaviors for the respective type, and included some helpful projects to assist developers in implementing device-specific functionalities. For example:

```
// Launchers (Manufacturer-introduced Feature Adaptation): Some customized systems offer additional badge functionality to display the number of unread messages on the home screen. Additionally, some customized systems require setting shortcuts through special APIs.
// Useful Project (Package Name): me.leolin.shortcutbadger, com.onesignal.shortcutbadger
```

Developers can gain a certain understanding of device-specific behaviors through these comments, rule contents, and our paper.
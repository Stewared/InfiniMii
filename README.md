# InfiniMii
Browse, share, and download Miis
Convert from any Mii format to any other format
See the average face across all Miis uploaded
Make Special Miis on a whim
Work with the Miis inside Amiibos
Store up to 50 private Miis for access from any device with a web browser
Transfer Miis between systems with no limitations
Backport 3DS Miis to the Wii
Comprehensive guide to transfer Miis directly to and from any console without ever modding it
Generate and scan QR codes
Build your own with the equally open source [MiiJS](https://github.com/KestronProgramming/MiiJS)

# Running Your Own
## Installing
```bash
git clone https://github.com/KestronProgramming/InfiniMii
cd InfiniMii
npm i
```
## Make env.json
The email instructions and code are designed for use with Zoho Mail, and mileage may vary for other email providers.
```json
{
    "email":"EMAIL THE SITE WILL LOG INTO",
    "emailPass":"PASSWORD TO THAT EMAIL",
    "salt":"ANY PHRASE YOU LIKE",
    "hookUrl":"DISCORD WEBHOOK FOR POSTING MODDABLE ACTIONS TO",
    "privateMiiLimit":50,
    "baseUrl":"THE URL YOUR SITE IS HOSTED FROM",
    "discordInvite":"AN INVITE TO YOUR DISCORD SUPPORT SERVER",
    "githubLink":"https://github.com/KestronProgramming/InfiniMii"
}
```
## Make storage.json
```json
{
    "miis":[],
    "users":[],
    "highlightedMii":"",
    "highlightedMiiChangeDay":0,
    "bannedIPs":[],
    "privateMiis":{},
    "officialCategories":{}
}
```
Some fields will need to be manually edited once more data is made. A default Mii ID and such will need to be set. You can use MiiJS to get the necessary JSON if the site won't initialize without one. Paste the JSON into the miis array, and add the following fields to it. Add the ID you select (five characters) to (storage.json).highlightedMii
```json
{
    "id":"14849",
    "uploader":"USERNAME",
    "desc":"DESCRIPTION",
    "votes":1,
    "official":false,
    "uploadedOn":"148148148148",
    "console":"3DS"
}
```
Once you sign up for the website, find yourself in the `users` array, and add the 'moderator' and 'administrator' roles to the array.

## Running
```bash
node index.js
```
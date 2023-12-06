<?php
$keyID = $_POST['keyID'];
switch ($keyID) {
    case "8689982f-22ca-4afe-a0ce-abc43f06a2bf":
        echo '{
  "keys":[
    {
      "key_ID":"8689982f-22ca-4afe-a0ce-abc43f06a2bf",
      "key":"B2s+pwhnHDjXIlXVuOC423TRZZG8Ahe6t6cR+JUnxpk="
    }
  ]
}';
        break;
    case "ebda3721-ad57-4774-937f-efb6d6ac5f46":
        echo '{
  "keys":[
    {
      "key_ID":"ebda3721-ad57-4774-937f-efb6d6ac5f46",
      "key":"5dV1r7GCIdT5mVDR2\/XoHYJ9DcPVDAV\/s3h\/TO5cnyE="
    }
  ]
}';
        break;
    case "5d78c28c-85bf-4701-8fb0-31607dcdf479":
        echo '{
  "keys":[
    {
      "key_ID":"5d78c28c-85bf-4701-8fb0-31607dcdf479",
      "key":"aOf3KnknCfd9tH0ce6HUvBYxdw34bnhaRSx4f6OYq3Q="
    }
  ]
}';
        break;

default:
echo "Missing ID";
}
?>

function getKey() {
  const size = 32;
  const randomString = crypto.randomBytes(size).toString("hex");
  return randomString;
}

function myFunction() {
  const key = getKey();
  document.getElementById("demo").innerHTML = key;
}
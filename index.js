function getKey() {
  const size = parseInt(process.argv.slice(2)[0]) || 32;
  const randomString = crypto.randomBytes(size).toString("hex");
  return randomString;
}

function myFunction() {
  const key = getKey();
  document.getElementById("demo").innerHTML = key;
}
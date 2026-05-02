var header = `
	<header>
		<img src='banner.png' alt='InfiniMii' decoding='async'>
 	</header>
`;
var footer = `
	<footer>
    <ul>
      <li><a href="mailto:kestron@kestron.com">Contact</a></li>
      <li><a>Support</a></li>
      <li><a>Donate</a></li>
      <li><a href='https://discord.gg/k3yVkrrvez'>Discord</a></li>
    </ul>
 	</footer>
`;
var accountThing = `
	<div id="accountThing">
		Sign Up
 	</div>
`;
document.body.innerHTML = accountThing + header + document.body.innerHTML + footer;
// TODO: remove this?

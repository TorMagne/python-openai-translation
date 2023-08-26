const alerts = document.querySelectorAll(".alert");

alerts.forEach((alert) => {
	setTimeout(() => {
		alert.classList.add("hidden");
	}, 3000);
});

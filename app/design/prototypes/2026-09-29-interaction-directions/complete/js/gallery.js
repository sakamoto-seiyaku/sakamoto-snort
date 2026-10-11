document.querySelectorAll("[data-filter]").forEach(
  (b) =>
    (b.onclick = () => {
      document
        .querySelectorAll("[data-filter]")
        .forEach((x) => x.classList.toggle("active", x === b));
      document
        .querySelectorAll("[data-group]")
        .forEach(
          (s) =>
            (s.hidden =
              b.dataset.filter !== "all" &&
              b.dataset.filter !== s.dataset.group),
        );
    }),
);

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

document.querySelectorAll("[data-sample-frame]").forEach(
  (b) =>
    (b.onclick = () => {
      const f = document.getElementById(b.dataset.sampleFrame);
      f.contentWindow.postMessage({ type: "sakamoto:sample" }, location.origin);
      b.nextElementSibling.textContent = "正在加入样例…";
    }),
);

window.addEventListener("message", (e) => {
  if (e.origin !== location.origin || e.data?.type !== "sakamoto:sample-result")
    return;
  document.querySelectorAll("[data-sample-frame]").forEach((b) => {
    if (
      document.getElementById(b.dataset.sampleFrame).contentWindow === e.source
    )
      b.nextElementSibling.textContent = e.data.ok
        ? "已加入样例；在画面中读取新活动"
        : "当前运行已暂停，没有加入样例";
  });
});

document.querySelectorAll("[data-subscription-frame]").forEach((button) => {
  button.onclick = () => {
    const frame = document.getElementById(button.dataset.subscriptionFrame);
    frame.contentWindow.postMessage(
      {
        type: "sakamoto:subscription-sample",
        outcome: button.dataset.outcome,
        scheduled: button.dataset.scheduled === "true",
      },
      location.origin,
    );
    button
      .closest(".demo-controls")
      .querySelector(".sample-status").textContent = button.dataset.scheduled
      ? "已模拟检查时间；按画面中的自动更新设置处理"
      : "样例响应已准备；在画面中点击检查更新";
  };
});

// Keep each embedded page at its real device viewport, scaling only its frame.
for (const frame of document.querySelectorAll(
  ".tablet-frame,.desktop-frame,.window-frame",
)) {
  const [width, height] = frame.classList.contains("tablet-frame")
    ? [820, 1180]
    : frame.classList.contains("desktop-frame")
      ? [1440, 900]
      : [640, 760];
  const iframe = frame.querySelector("iframe");
  const resize = () => {
    const scale = frame.clientWidth / width;
    iframe.style.width = width + "px";
    iframe.style.height = height + "px";
    iframe.style.transform = "scale(" + scale + ")";
    frame.style.height = height * scale + "px";
  };
  new ResizeObserver(resize).observe(frame);
  resize();
}

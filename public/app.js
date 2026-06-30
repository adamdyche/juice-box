// Cart checkout. Sends the cart (including prices) from the browser to the server.
(function () {
  const btn = document.getElementById('checkout-btn');
  if (!btn) return;
  const out = document.getElementById('checkout-result');

  btn.addEventListener('click', async () => {
    const items = window.__CART__ || [];
    const coupon = document.getElementById('coupon').value.trim();
    out.textContent = 'Processing...';
    try {
      const r = await fetch('/cart/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items, coupon }),
      });
      const data = await r.json();
      if (data.ok) {
        out.textContent = `✅ Order #${data.orderId} placed. Charged $${data.total.toFixed(2)}` +
          (data.discount ? ` (coupon applied: ${(data.discount * 100)}% off)` : '');
      } else {
        out.textContent = '❌ ' + (data.error || 'Checkout failed');
      }
    } catch (e) {
      out.textContent = '❌ ' + e.message;
    }
  });
})();

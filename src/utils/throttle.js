// Implementation without leading or trailing options
export default function throttle (func, limit) {
  let ctx, args, result;
  let timeout = null;
  let previous = 0;

  const later = function() {
    previous = Date.now();
    timeout = null;
    result = func.apply(ctx, args);
    if (!timeout) context = args = null;
  };

  return function() {
    const now = Date.now();
    const remaining = limit - (now - previous);
    ctx = this;
    args = arguments;
    if (remaining <=0 || remaining > limit) {
      if (timeout) {
        timeout = null;
      }
      previous = now;
      result = func.apply(ctx, args);
      if (!timeout) {
        ctx = args = null;
      }
    }
    return result;
  };
};

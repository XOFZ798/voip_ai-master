import asyncio
from langchain_openai import ChatOpenAI
import os
from src.logger_config import logger, PATH
from src.payment_report import PaymentSms
import json

avalai_error = os.path.join(PATH, "audio", "important_avalai_error")


class AvalAiApi:
    def __init__(self, API_KEY):
        self.API_KEY = API_KEY
        self.chat = ChatOpenAI(
            model="gpt-4o-mini",
            base_url="https://api.avalai.ir/v1",
            api_key=self.API_KEY,
            temperature=0
        )

        self.messages = [
            {"role": "system",
             "content": "شما یک دستیار هوشمند هستید که اطلاعات سردخانه را تحلیل می‌کنید و به کاربر گزارش می‌دهید."
                        "اگر کاربر یکی از  موارد رطوبت (HUM1)، وضعیت برق (Vbat)، دما (TEMP1) و شارژ سیم‌کارت (Credit) را درخواست کرد، طبق دستور عمل زیر گزارش بهش بده "
                        "اگر کاربر چیزی غیر از این موارد پرسید، به صورت روان و فارسی جواب بده (اصلا از کلمات انگلیسی استفاده نکن) "
                        "\n\n### دستور عمل:\n"
                        "1. **Vbat (وضعیت برق)**: اگر مقدار آن `0.0` باشد، برق وصل و وضعیت سالن مناسب است. در غیر این صورت، برق قطع و سردخانه غیرفعال است.\n"
                        "2. **HUM1 (رطوبت)**: اگر مقدار `NC` باشد، رطوبتی وجود ندارد. در غیر این صورت، مقدار رطوبت را درصدی گزارش بده.\n"
                        "3. **TEMP1 (دما)**: دما رو به درجه بده. اگر دما بالاتر از صفر بود اخطار هم بده دمای زیر صفر افزایش یافته.\n"
                        "4. **Credit (شارژ سیم‌کارت)**: مقدار عددی اعتبار سیم‌کارت را اعلام کن.\n"
                        "5. **Relays (وضعیت دستگاه‌ها)**: بسته به مقدار، وضعیت سردخانه را اعلام کن.\n"
                        "*Relays مقادیر :* \n"
                        "0x000 = همه دستگاه های سردخانه خاموش یا در حالت اتومات \n"
                        "0x001 = کمپرسور و سالن زیر صفر روشن \n"
                        "0x004 = سیستم در حال دیفراست و برفک زدایی \n"
                        "0x008 = سالن بالای صفر روشن \n"
                        "0x007 = کلیه قسمت های زیر صفر و بالای صفر روشن و درحال کار \n"
                        "0x005 = سردخانه در حال دیفراست است \n"
                        "6. **Inputs (ورودی‌های کنترلی)**: بسته به مقدار، مشکلات احتمالی سردخانه را گزارش بده.\n"
                        "*Inputs مقادیر :* \n"
                        "0x01 = کنترل بار کمپرسور عمل کرده و سرخانه خاموش  \n"
                        "0x02 = سیستم با کمبود گاز مواجه شده و کمپرسور خاموش  \n"
                        "0x04 = حرارت بالای موتور باعث عملکرد ترمیستور حفاظتی شده و کمپرسور خاموش شده  \n"
                        "0x08 = رق ورودی سرخانه نقص دارد و باعث خاموش شدن سردخانه شده است لطفا برای رفع ایراد ورودی برق را چک کنید  \n"
                        "## اگر سردخانه در حالت دیفراست بود هیچ گزارشی از inputs دیگه نده"
                        "## کاربر اگر یکی از اون 4 تا رو درخواست کرد تو درجواب گزارش inputs و relays هم پیوست کن و بده"
                        "\n * هروقت مکالمت با کاربر تموم شد فقط کلمه exit خالی برگردون * \n"
                        "\n * مکالمه رو تا زمانی که کاربر نگفته تمومه ادامه بده و ببین درخواست دیگه ای داره یا نه * \n"
             }
        ]
        self.components = {
            "رطوبت": "HUM1",
            "وضعیت برق": "Vbat",
            "دما": "TEMP1",
            "شارژ سیم‌کارت": "Credit"
        }
        self.max_messages = 5  # To prevent excessive memory usage

    async def start_conversation(self, raw_data, user_input):
        """Handles user input, sends it to AI, and returns the recognized command or response."""
        try:
            self.messages.append({"role": "system", "content": f"### داده‌های دریافتی از سردخانه:\n{raw_data}"})

            self.messages.append({"role": "user", "content": user_input})

            # Ensure messages list doesn't grow indefinitely
            if len(self.messages) > self.max_messages:
                self.messages.pop(1)  # Remove oldest user message (keep system message)

            # Set a timeout for AI response
            response = await asyncio.wait_for(
                asyncio.to_thread(self.chat.invoke, self.messages), timeout=8
            )

            if not response or not hasattr(response, "content"):
                raise ValueError("Invalid response received from Aval-AI.")

            assistant_reply = response.content
            self.messages.append({"role": "assistant", "content": assistant_reply})

            status, answer_analys = self.goodby(assistant_reply)
            return status, answer_analys

        except asyncio.TimeoutError:
            raise NotImplementedError(("Aval Ai Timeout ERROR", avalai_error))
        except Exception as e:
            # Check if the exception has an 'error' attribute
            if hasattr(e, "error"):
                error_data = e.error  # Extract error dictionary if available
            elif hasattr(e, "response") and hasattr(e.response, "json"):
                try:
                    error_data = e.response.json()  # Try getting JSON response if available
                except Exception:
                    error_data = None  # JSON parsing failed
            else:
                error_data = None

            if error_data and error_data.get("error", {}).get("code") == "quota_exceeded_error":
                send_sms = PaymentSms("اعتبار وب سرویس aval ai به پایان رسیده است")
                await send_sms.send_reports()
                raise NotImplementedError((f"AvalAi : {str(e)}", avalai_error))

            raise NotImplementedError((f"AvalAi Exception: {str(e)}", avalai_error))

    def analyze_user_input(self, assistant_reply):
        """Analyzes the AI response to detect the requested information."""
        for component, word in self.components.items():
            if word in assistant_reply:
                return True, word
        return None, assistant_reply

    def goodby(self, assistant_reply):
        if "exit" in assistant_reply:
            return None, assistant_reply
        else:
            return True, assistant_reply

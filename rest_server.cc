/*
 * SPDX-FileCopyrightText: 2016 Mathieu Stefani
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
   Mathieu Stefani, 07 février 2016

   Example of a REST endpoint with routing
*/

#include <algorithm>

#include <exception>
#include <pistache/client.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

using namespace Pistache;

void printCookies(const Http::Request &req) {
  auto cookies = req.cookies();
  std::cout << "Cookies: [" << std::endl;
  const std::string indent(4, ' ');
  for (const auto &c : cookies) {
    std::cout << indent << c.name << " = " << c.value << std::endl;
  }
  std::cout << "]" << std::endl;
}

namespace Generic {

void handleReady(const Rest::Request &, Http::ResponseWriter response) {
  response.send(Http::Code::Ok, "1");
}

} // namespace Generic

using HttpClient = Http::Experimental::Client;

static HttpClient client;

class StatsEndpoint {
public:
  explicit StatsEndpoint(Address addr)
      : httpEndpoint(std::make_shared<Http::Endpoint>(addr)) {}

  void init(size_t thr = 2) {
    auto opts = Http::Endpoint::options().threads(static_cast<int>(thr));
    httpEndpoint->init(opts);
    setupRoutes();
  }

  void start() {
    httpEndpoint->setHandler(router.handler());
    httpEndpoint->serve();
  }

private:
  void setupRoutes() {
    using namespace Rest;

    Routes::Post(router, "/record/:name/:value?",
                 Routes::bind(&StatsEndpoint::doRecordMetric, this));
    Routes::Get(router, "/value/:name",
                Routes::bind(&StatsEndpoint::doGetMetric, this));
    Routes::Get(router, "/ready", Routes::bind(&Generic::handleReady));
    Routes::Get(router, "/auth", Routes::bind(&StatsEndpoint::doAuth, this));
    Routes::Get(router, "/async_request",
                Routes::bind(&StatsEndpoint::doAsyncRequest, this));
    Routes::Get(router, "/another_address",
                Routes::bind(&StatsEndpoint::doDelayedResponse, this));
  }

  void doRecordMetric(const Rest::Request &request,
                      Http::ResponseWriter response) {
    auto name = request.param(":name").as<std::string>();

    Guard guard(metricsLock);
    auto it =
        std::find_if(metrics.begin(), metrics.end(), [&](const Metric &metric) {
          return metric.name() == name;
        });

    int val = 1;
    if (request.hasParam(":value")) {
      auto value = request.param(":value");
      val = value.as<int>();
    }

    if (it == std::end(metrics)) {
      metrics.emplace_back(std::move(name), val);
      response.send(Http::Code::Created, std::to_string(val));
    } else {
      auto &metric = *it;
      metric.incr(val);
      response.send(Http::Code::Ok, std::to_string(metric.value()));
    }
  }

  void doGetMetric(const Rest::Request &request,
                   Http::ResponseWriter response) {
    auto name = request.param(":name").as<std::string>();

    Guard guard(metricsLock);
    auto it =
        std::find_if(metrics.begin(), metrics.end(), [&](const Metric &metric) {
          return metric.name() == name;
        });

    if (it == std::end(metrics)) {
      response.send(Http::Code::Not_Found, "Metric does not exist");
    } else {
      const auto &metric = *it;
      response.send(Http::Code::Ok, std::to_string(metric.value()));
    }
  }

  void doAuth(const Rest::Request &request, Http::ResponseWriter response) {
    printCookies(request);
    response.cookies().add(Http::Cookie("lang", "en-US"));
    response.send(Http::Code::Ok);
  }

  static auto getPeer(const Http::ResponseWriter &response)
      -> std::shared_ptr<Tcp::Peer> {
    try {
      return response.peer();
    } catch (...) {
    }
    return nullptr;
  }

  void doAsyncRequest(const Rest::Request &request,
                      Http::ResponseWriter response) {

    using namespace Pistache::Http;

    std::string address = "http://127.0.0.1:1234/another_address";
    auto resp_srv2 = client.get(address).send();

    auto responseHeap = std::make_shared<ResponseWriter>(std::move(response));

    resp_srv2.then(
        [responseHeap](Response srvresponse) mutable {
          auto peerLocked = getPeer(*responseHeap);
          if (!peerLocked) {
            // Client disconnected
            return;
          }

          responseHeap->send(srvresponse.code(), srvresponse.body());
        },
        [responseHeap](std::exception_ptr exc) mutable {
          auto peerLocked = getPeer(*responseHeap);

          if (!peerLocked) {
            // Client disconnected
            return;
          }

          PrintException excPrinter;
          excPrinter(std::move(exc));

          // set mime type...
          responseHeap->send(Code::Internal_Server_Error, "{}");
        });
  }

  void doDelayedResponse(const Rest::Request &request,
                         Http::ResponseWriter response) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::string strresp;

    strresp.resize(256, 'A');

    response.send(Http::Code::Ok, strresp);
  }

  class Metric {
  public:
    explicit Metric(std::string name, int initialValue = 1)
        : name_(std::move(name)), value_(initialValue) {}

    int incr(int n = 1) {
      int old = value_;
      value_ += n;
      return old;
    }

    int value() const { return value_; }

    const std::string &name() const { return name_; }

  private:
    std::string name_;
    int value_;
  };

  using Lock = std::mutex;
  using Guard = std::lock_guard<Lock>;
  Lock metricsLock;
  std::vector<Metric> metrics;

  std::shared_ptr<Http::Endpoint> httpEndpoint;
  Rest::Router router;
};

int main(int argc, char *argv[]) {
  Port port(9080);

  client.init(HttpClient::options().threads(8));

  int thr = 2;

  if (argc >= 2) {
    port = static_cast<uint16_t>(std::stol(argv[1]));

    if (argc == 3)
      thr = std::stoi(argv[2]);
  }

  Address addr(Ipv4::any(), port);

  std::cout << "Cores = " << hardware_concurrency() << std::endl;
  std::cout << "Using " << thr << " threads" << std::endl;

  StatsEndpoint stats(addr);

  stats.init(thr);
  stats.start();
}

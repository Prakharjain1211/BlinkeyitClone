import React from "react";
import logo from "../assets/logo.png";
import Search from "./Search";
import { Link } from "react-router-dom";
const Header = () => {
  return (
    <header className="h-20 sticky top-0">
      <div className="container mx-auto flex items-center h-full px-2 justify-between ">
        {/**logo*/}
        <div className="h-full">
          <Link to={"/"} className="h-full flex items-center justify-center">
            <img
              src={logo}
              alt="logo"
              height={60}
              width={170}
              className="hidden lg:block"
            />
            <img
              src={logo}
              alt="logo"
              height={60}
              width={170}
              className="lg:hidden"
            />
          </Link>
        </div>
        {/**Search*/}
        <div>
          <Search />
        </div>
        {/**login and my cart*/}
        <div className="">login and cart</div>
      </div>
    </header>
  );
};

export default Header;

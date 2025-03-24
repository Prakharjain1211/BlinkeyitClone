import React, { useEffect, useState } from "react";
import { IoSearch } from "react-icons/io5";
import { useLocation, useNavigate } from "react-router-dom";
import { TypeAnimation } from "react-type-animation";

const Search = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [isSearchPage, setIsSearchPage] = useState(false);

  useEffect(() => {
    const isSearch = location.pathname === "/search";
    setIsSearchPage(isSearch);
  }, [location]);

  const redirectToSearchPage = () => {
    navigate("/search");
  };
  return (
    <div className="w-full min-w-[420px] h-12 rounded-lg border overflow-hidden flex items-center text-neutral-500 bg-slate-50">
      <button className="flex justify-center items-center h-full p-3">
        <IoSearch size={22} />
      </button>
      <div className="w-full h-full">
        {!isSearchPage ? (
          //Not in search page
          <div onClick={redirectToSearchPage} className="w-full h-full flex items-center">
            <TypeAnimation
              sequence={[
                // Same substring at the start will only be typed out once, initially
                'Search "milk"',
                1000, // wait 1s before replacing "Mice" with "Hamsters"
                'Search "bread"',
                1000,
                'Search "sugar"',
                1000,
                'Search "panner"',
                1000,
                'Search "chocolate"',
                1000,
                'Search "curd"',
                1000,
                'Search "rice"',
                1000,
                'Search "egg"',
                1000,
                'Search "chips"',
              ]}
              wrapper="span"
              speed={50}
              repeat={Infinity}
            />
          </div>
        ) : (
          //In search page
          <div className="w-full h-full">
            <input type="text" placeholder="Search for atta dal and more." autoFocus className="bg-transparent w-full h-full outline-none"/>
          </div>
        )}
      </div>
    </div>
  );
};

export default Search;
